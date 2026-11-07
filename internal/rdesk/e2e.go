package rdesk

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// End-to-end session encryption (#130, ADR-0103).
//
// WireGuard already encrypts and authenticates every packet between two
// devices. The second layer protects the session when the TCP stream is
// visible in plaintext somewhere on the way: a subnet router or exit node
// that forwards tunnel traffic, or a compromised relay host that also
// holds tunnel keys. Protocol version 2 adds an ephemeral X25519 key to
// hello; the server answers with its own ephemeral key in a kex message
// and from then on every message in both directions is one AES-256-GCM
// sealed record with a per-direction key and a counter nonce. Both ends
// derive a six-digit verification code from the transcript; the consent
// prompt and the viewer show it so a person can compare them. A
// man-in-the-middle that replaces the keys produces different codes.

const (
	// ProtocolVersionE2E is the hello version with the second encryption
	// layer. ProtocolVersion (1) is the plain version of ADR-0055.
	ProtocolVersionE2E = 2

	// msgKex carries the server's ephemeral public key (plaintext).
	msgKex msgType = 0x8a
	// msgSealed wraps one complete inner message in both directions.
	msgSealed msgType = 0xe0

	e2eKeyLen    = 32
	sealOverhead = 16 // AES-GCM tag
)

var e2eLabel = []byte("openscale-rdesk-e2e-v1\x00")

// wire reads and writes messages, sealing them once keys are set. Reads
// happen on one goroutine; seal must be called under the writer's lock.
type wire struct {
	br    *bufio.Reader
	rx    cipher.AEAD
	tx    cipher.AEAD
	rxSeq uint64
	txSeq uint64
}

func seqNonce(seq uint64) []byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

// read returns the next message whose inner payload is at most limit
// bytes.
func (w *wire) read(limit int) (msgType, []byte, error) {
	if w.rx == nil {
		return readMsg(w.br, limit)
	}
	t, p, err := readMsg(w.br, limit+headerLen+sealOverhead)
	if err != nil {
		return 0, nil, err
	}
	if t != msgSealed || w.rxSeq == ^uint64(0) {
		return 0, nil, fmt.Errorf("%w: şifresiz ileti", ErrProtocol)
	}
	pt, err := w.rx.Open(p[:0], seqNonce(w.rxSeq), p, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: şifreli ileti doğrulanamadı", ErrProtocol)
	}
	w.rxSeq++
	if len(pt) < headerLen {
		return 0, nil, ErrProtocol
	}
	n := binary.BigEndian.Uint32(pt[1:headerLen])
	if int64(n) != int64(len(pt)-headerLen) || int64(n) > int64(limit) || msgType(pt[0]) == msgSealed {
		return 0, nil, ErrProtocol
	}
	return msgType(pt[0]), pt[headerLen:], nil
}

// seal wraps a complete message when encryption is on.
func (w *wire) seal(msg []byte) []byte {
	if w.tx == nil {
		return msg
	}
	out := appendHeader(make([]byte, 0, headerLen+len(msg)+sealOverhead), msgSealed)
	out = w.tx.Seal(out, seqNonce(w.txSeq), msg, nil)
	w.txSeq++
	return finishMsg(out)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// e2eKeys is the result of the key exchange.
type e2eKeys struct {
	c2s, s2c cipher.AEAD
	code     string
}

// deriveE2E binds the keys to the whole hello (mode, monitor, client key)
// and the server key, so neither can be changed without changing the
// verification code.
func deriveE2E(priv *ecdh.PrivateKey, peerPub []byte, helloPayload, serverPub []byte) (e2eKeys, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return e2eKeys{}, ErrProtocol
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		// Low-order points give an all-zero secret.
		return e2eKeys{}, ErrProtocol
	}
	h := sha256.New()
	h.Write(e2eLabel)
	h.Write(helloPayload)
	h.Write(serverPub)
	th := h.Sum(nil)
	key := func(info string, n int) ([]byte, error) {
		return hkdf.Key(sha256.New, shared, th, info, n)
	}
	c2sKey, err := key("rdesk c2s", e2eKeyLen)
	if err != nil {
		return e2eKeys{}, err
	}
	s2cKey, err := key("rdesk s2c", e2eKeyLen)
	if err != nil {
		return e2eKeys{}, err
	}
	sas, err := key("rdesk sas", 8)
	if err != nil {
		return e2eKeys{}, err
	}
	var k e2eKeys
	if k.c2s, err = newGCM(c2sKey); err != nil {
		return e2eKeys{}, err
	}
	if k.s2c, err = newGCM(s2cKey); err != nil {
		return e2eKeys{}, err
	}
	n := binary.BigEndian.Uint64(sas) % 1_000_000
	k.code = fmt.Sprintf("%03d %03d", n/1000, n%1000)
	return k, nil
}

func newE2EKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// serverKex answers a version 2 hello: it returns the kex message to send
// and the keys (rx: client to server, tx: server to client).
func serverKex(helloPayload, clientPub []byte) ([]byte, e2eKeys, error) {
	priv, err := newE2EKey()
	if err != nil {
		return nil, e2eKeys{}, err
	}
	pub := priv.PublicKey().Bytes()
	k, err := deriveE2E(priv, clientPub, helloPayload, pub)
	if err != nil {
		return nil, e2eKeys{}, err
	}
	return encodeMsg(msgKex, pub), k, nil
}

// helloV2 is hello with the client's ephemeral key.
func (h hello) encodeV2(pub []byte) []byte {
	p := append([]byte(helloMagic), ProtocolVersionE2E, uint8(h.mode), monitorByte(h.monitor), uint8(h.maxFPS), uint8(h.scale))
	return encodeMsg(msgHello, append(p, pub...))
}

// decodeHelloAny accepts version 1 and version 2 hellos and returns the
// client's public key for version 2.
func decodeHelloAny(p []byte) (hello, []byte, error) {
	if len(p) < len(helloMagic)+1 {
		return hello{}, nil, ErrProtocol
	}
	switch p[len(helloMagic)] {
	case ProtocolVersion:
		h, err := decodeHello(p)
		return h, nil, err
	case ProtocolVersionE2E, ProtocolVersionExt, ProtocolVersionLogin:
		v := p[len(helloMagic)]
		if len(p) != len(helloMagic)+5+e2eKeyLen {
			return hello{}, nil, ErrProtocol
		}
		base := slicesClone(p[:len(helloMagic)+5])
		base[len(helloMagic)] = ProtocolVersion
		h, err := decodeHello(base)
		if err != nil {
			return hello{}, nil, err
		}
		h.version = v
		return h, slicesClone(p[len(helloMagic)+5:]), nil
	}
	// Unknown versions are answered with the supported one.
	return hello{version: p[len(helloMagic)]}, nil, nil
}

func slicesClone(b []byte) []byte { return append([]byte(nil), b...) }
