package p2psend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/filesend"
)

// Route modes.
const (
	// RouteAuto tries the receiver directly and falls back to the onion
	// route when one is given.
	RouteAuto = "auto"
	// RouteDirect only connects to the receiver.
	RouteDirect = "direct"
	// RouteOnion only uses the onion route.
	RouteOnion = "onion"
)

const (
	dialTimeout       = 10 * time.Second
	acceptWaitTimeout = 6 * time.Minute
	finalReplyTimeout = 10 * time.Minute
	// maxStripBytes bounds files whose metadata is removed in memory.
	maxStripBytes = 256 << 20
)

// Target is the receiving device.
type Target struct {
	Name string
	Key  Key
	Addr netip.AddrPort
}

// SendOptions tune one transfer.
type SendOptions struct {
	// Name overrides the file name shown to the receiver.
	Name string
	// Route is RouteAuto (default), RouteDirect or RouteOnion.
	Route string
	// Hops is the onion route (MinHops..MaxHops trusted members).
	Hops []Hop
	// KeepMetadata disables metadata removal (#658; on by default).
	KeepMetadata bool
	// Progress is called with the bytes the receiver holds.
	Progress func(done, total int64)
	// Dial opens connections; nil uses net.Dialer.
	Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// Registry, if set, records the transfer for the panel.
	Registry *Registry
	// Random is the key source; nil uses crypto/rand.
	Random io.Reader
	// IdleTimeout aborts a stalled stream (default 60 s).
	IdleTimeout time.Duration
}

// SendResult describes a completed transfer.
type SendResult struct {
	Name     string // final name in the receiver's quarantine
	Size     int64
	Resumed  int64
	Path     string // PathDirect or PathOnion
	Hops     int
	Stripped bool
}

// source is the file content after optional metadata removal.
type source struct {
	r        io.ReaderAt
	size     int64
	digest   []byte
	stripped bool
	close    func() error
}

func openSource(path string, keep bool) (*source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dosya açılamadı: %w", err)
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, errors.New("yalnızca normal dosyalar gönderilebilir")
	}
	if !keep && st.Size() <= maxStripBytes {
		data, err := io.ReadAll(io.LimitReader(f, maxStripBytes+1))
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		clean, err := StripForSend(path, data)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if !bytes.Equal(clean, data) {
			_ = f.Close()
			sum := sha256.Sum256(clean)
			return &source{r: bytes.NewReader(clean), size: int64(len(clean)), digest: sum[:], stripped: true,
				close: func() error { return nil }}, nil
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &source{r: f, size: n, digest: h.Sum(nil), close: f.Close}, nil
}

// StripForSend removes image and document metadata (#658): location and
// camera data from JPEG and PNG, author fields from Office files and PDF.
// Formats it cannot clean are refused rather than sent with metadata.
func StripForSend(name string, data []byte) ([]byte, error) {
	clean, err := filesend.StripMetadata(name, data, filesend.MetadataAll)
	if err != nil {
		return nil, err
	}
	return filesend.StripDocumentMetadata(name, clean)
}

// Send delivers path to target with end-to-end encryption.
func Send(ctx context.Context, id Identity, target Target, path string, opts *SendOptions) (SendResult, error) {
	o := SendOptions{}
	if opts != nil {
		o = *opts
	}
	if o.Route == "" {
		o.Route = RouteAuto
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.Dial == nil {
		o.Dial = func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", a.String())
		}
	}
	if target.Key.IsZero() || !target.Addr.IsValid() {
		return SendResult{}, errors.New("alıcı cihazın anahtarı ve adresi gerekli")
	}
	switch o.Route {
	case RouteAuto, RouteDirect:
	case RouteOnion:
		if len(o.Hops) < MinHops {
			return SendResult{}, fmt.Errorf("%w: soğan yolu için en az %d güvenilen ara cihaz seçin", ErrRoute, MinHops)
		}
	default:
		return SendResult{}, fmt.Errorf("bilinmeyen yol türü %q", o.Route)
	}
	name := o.Name
	if name == "" {
		name = filepath.Base(path)
	}
	if _, err := filesend.SanitizeName(name); err != nil {
		return SendResult{}, err
	}
	src, err := openSource(path, o.KeepMetadata)
	if err != nil {
		return SendResult{}, err
	}
	defer src.close()

	reg := o.Registry.start(TransferView{Outgoing: true, Peer: target.Name, Name: name, Size: src.size,
		State: StateWaiting, Stripped: src.stripped})
	res, err := sendVia(ctx, id, target, name, src, &o, reg)
	reg.finish(err)
	return res, err
}

func sendVia(ctx context.Context, id Identity, target Target, name string, src *source, o *SendOptions, reg *handle) (SendResult, error) {
	var conn net.Conn
	path, hops := PathDirect, 0
	var err error
	if o.Route != RouteOnion {
		dctx, cancel := context.WithTimeout(ctx, dialTimeout)
		conn, err = o.Dial(dctx, target.Addr)
		cancel()
		if err != nil && (o.Route == RouteDirect || len(o.Hops) < MinHops) {
			return SendResult{}, fmt.Errorf("alıcıya bağlanılamadı: %w", err)
		}
	}
	var prefix []byte
	if conn == nil {
		onion, err := BuildOnion(o.Hops, target.Addr, target.Key, o.Random)
		if err != nil {
			return SendResult{}, err
		}
		dctx, cancel := context.WithTimeout(ctx, dialTimeout)
		conn, err = o.Dial(dctx, o.Hops[0].Addr)
		cancel()
		if err != nil {
			return SendResult{}, fmt.Errorf("ilk ara cihaza bağlanılamadı: %w", err)
		}
		prefix, path, hops = onion, PathOnion, len(o.Hops)
	}
	defer conn.Close()
	reg.set(func(v *TransferView) { v.Path, v.Hops = path, hops })
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	e, keys, err := senderSession(id, target.Key, o.Random)
	if err != nil {
		return SendResult{}, err
	}
	defer keys.wipe()
	tid := transferID(target.Key, src.digest, src.size)
	hb, err := encodeHeader(header{V: wireVersion, ID: hex.EncodeToString(tid), Name: name, Size: src.size,
		SHA256: hex.EncodeToString(src.digest), Chunk: ChunkSize, Stripped: src.stripped})
	if err != nil {
		return SendResult{}, err
	}
	sealed, err := seal(&keys.header, domainHeader, 0, hb, []byte(magic))
	clear(hb)
	if err != nil {
		return SendResult{}, err
	}
	hello := append(prefix, encodeFileHello(fileHello{sender: id.Public, ephemeral: e, sealed: sealed})...)
	_ = conn.SetWriteDeadline(time.Now().Add(dialTimeout + o.IdleTimeout))
	if _, err := conn.Write(hello); err != nil {
		return SendResult{}, ctxErr(ctx, fmt.Errorf("gönderilemedi: %w", err))
	}
	in := &replyChannel{key: &keys.reply}
	_ = conn.SetReadDeadline(time.Now().Add(acceptWaitTimeout))
	r, err := in.read(conn)
	if err != nil {
		return SendResult{}, ctxErr(ctx, fmt.Errorf("alıcı yanıt vermedi: %w", err))
	}
	if r.Status != statusAccept {
		return SendResult{}, statusErr(r.Status)
	}
	total := numChunks(src.size)
	if r.Offset >= total {
		return SendResult{}, ErrProtocol
	}
	resumed := int64(r.Offset) * ChunkSize
	reg.set(func(v *TransferView) { v.State = StateSending; v.Resumed = resumed })
	plain := make([]byte, ChunkSize)
	defer clear(plain)
	done := resumed
	for i := r.Offset; i < total; i++ {
		clear(plain)
		n := chunkLen(src.size, i)
		if n > 0 {
			if _, err := src.r.ReadAt(plain[:n], int64(i)*ChunkSize); err != nil && !(errors.Is(err, io.EOF) && n > 0) {
				return SendResult{}, fmt.Errorf("dosya okunamadı: %w", err)
			}
		}
		ct, err := seal(&keys.data, domainData, i, plain, chunkAD(tid, i == total-1))
		if err != nil {
			return SendResult{}, err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(o.IdleTimeout))
		if _, err := conn.Write(ct); err != nil {
			return SendResult{}, ctxErr(ctx, fmt.Errorf("aktarım kesildi: %w", err))
		}
		done += int64(n)
		reg.progress(done)
		if o.Progress != nil {
			o.Progress(done, src.size)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(finalReplyTimeout))
	r, err = in.read(conn)
	if err != nil {
		return SendResult{}, ctxErr(ctx, fmt.Errorf("son yanıt alınamadı: %w", err))
	}
	if r.Status != statusOK {
		return SendResult{}, statusErr(r.Status)
	}
	return SendResult{Name: r.Name, Size: src.size, Resumed: resumed, Path: path, Hops: hops, Stripped: src.stripped}, nil
}

func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
