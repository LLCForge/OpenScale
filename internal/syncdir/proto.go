package syncdir

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"time"
)

// Wire protocol (ADR-0104). Requests and responses are frames of a 4-byte
// big-endian length and a JSON object (at most 1 MiB). File and object
// bytes follow a response (get) or a "ready" answer (put) raw; a put ends
// with a trailer frame carrying the SHA-256 of the bytes sent. One
// connection carries any number of requests in turn.

const (
	protoVersion  = 1
	maxFrame      = 1 << 20
	indexPageSize = 512 << 10
	maxListPage   = 5000
	maxHasNames   = 1000
	requestIdle   = 2 * time.Minute
	dataIdle      = 60 * time.Second
	dialTimeout   = 10 * time.Second
)

// Operations.
const (
	opIndex = "index"
	opGet   = "get"
	opHas   = "bhas"
	opPut   = "bput"
	opFetch = "bget"
	opList  = "blist"
	opDel   = "bdel"
)

// Status values.
const (
	stOK       = "ok"
	stReady    = "ready"
	stDenied   = "denied"
	stNotFound = "notfound"
	stChanged  = "changed"
	stQuota    = "quota"
	stBad      = "badrequest"
	stError    = "error"
)

type request struct {
	V      int      `json:"v"`
	Op     string   `json:"op"`
	Folder string   `json:"folder,omitempty"`
	Path   string   `json:"path,omitempty"`
	Hash   string   `json:"hash,omitempty"`
	After  string   `json:"after,omitempty"`
	Store  string   `json:"store,omitempty"`
	Kind   string   `json:"kind,omitempty"`
	Name   string   `json:"name,omitempty"`
	Names  []string `json:"names,omitempty"`
	Size   int64    `json:"size,omitempty"`
	SHA256 string   `json:"sha256,omitempty"`
}

type wireEntry struct {
	P string `json:"p"`
	Entry
}

type response struct {
	Status  string      `json:"status"`
	Error   string      `json:"error,omitempty"`
	Entries []wireEntry `json:"entries,omitempty"`
	More    bool        `json:"more,omitempty"`
	Size    int64       `json:"size,omitempty"`
	Names   []string    `json:"names,omitempty"`
	Have    []bool      `json:"have,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxFrame {
		return ErrProtocol
	}
	buf := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body)))
	_, err = w.Write(append(buf, body...))
	return err
}

func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return ErrProtocol
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return ErrProtocol
	}
	return nil
}

type deadlineReader struct {
	c    net.Conn
	r    io.Reader
	idle time.Duration
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	_ = d.c.SetReadDeadline(time.Now().Add(d.idle))
	return d.r.Read(p)
}

type deadlineWriter struct {
	c    net.Conn
	idle time.Duration
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	_ = d.c.SetWriteDeadline(time.Now().Add(d.idle))
	return d.c.Write(p)
}
