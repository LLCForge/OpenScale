package dbuswire

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// MessageType is the kind of a message.
type MessageType byte

// Message types.
const (
	TypeMethodCall   MessageType = 1
	TypeMethodReturn MessageType = 2
	TypeError        MessageType = 3
	TypeSignal       MessageType = 4
)

// Message flags.
const (
	FlagNoReplyExpected byte = 0x1
	FlagNoAutoStart     byte = 0x2
	// FlagAllowInteractiveAuthorization lets the callee ask the user
	// (polkit, the portal's dialog).
	FlagAllowInteractiveAuthorization byte = 0x4
)

// Header field codes.
const (
	fieldPath        = 1
	fieldInterface   = 2
	fieldMember      = 3
	fieldErrorName   = 4
	fieldReplySerial = 5
	fieldDestination = 6
	fieldSender      = 7
	fieldSignature   = 8
	fieldUnixFDs     = 9
)

// Message is one D-Bus message.
type Message struct {
	Type        MessageType
	Flags       byte
	Serial      uint32
	Path        ObjectPath
	Interface   string
	Member      string
	ErrorName   string
	ReplySerial uint32
	Destination string
	Sender      string
	Signature   Signature
	// UnixFDs is the number of file descriptors the message carries.
	UnixFDs uint32
	Body    []any
	// Files are the received file descriptors in index order (UnixFD
	// values point into it). The receiver owns them and must close them.
	Files []*os.File
}

// CloseFiles closes the received file descriptors.
func (m *Message) CloseFiles() {
	for _, f := range m.Files {
		if f != nil {
			_ = f.Close()
		}
	}
	m.Files = nil
}

// validate checks the header fields the message type needs and every
// name in them.
func (m *Message) validate() error {
	if m.Serial == 0 {
		return malformed("seri numarası sıfır")
	}
	switch m.Type {
	case TypeMethodCall:
		if m.Path == "" || m.Member == "" {
			return malformed("yöntem çağrısında yol veya üye yok")
		}
	case TypeMethodReturn:
		if m.ReplySerial == 0 {
			return malformed("yanıtta yanıt seri numarası yok")
		}
	case TypeError:
		if m.ErrorName == "" || m.ReplySerial == 0 {
			return malformed("hata iletisinde ad veya yanıt seri numarası yok")
		}
	case TypeSignal:
		if m.Path == "" || m.Interface == "" || m.Member == "" {
			return malformed("sinyalde yol, arayüz veya üye yok")
		}
		if m.Path == "/org/freedesktop/DBus/Local" {
			return malformed("ayrılmış yol")
		}
	default:
		return malformed("bilinmeyen ileti türü %d", m.Type)
	}
	if m.Path != "" && !ValidObjectPath(string(m.Path)) {
		return malformed("geçersiz yol")
	}
	if m.Interface != "" && !ValidInterfaceName(m.Interface) {
		return malformed("geçersiz arayüz adı")
	}
	if m.Member != "" && !ValidMemberName(m.Member) {
		return malformed("geçersiz üye adı")
	}
	if m.ErrorName != "" && !ValidInterfaceName(m.ErrorName) {
		return malformed("geçersiz hata adı")
	}
	if m.Destination != "" && !ValidBusName(m.Destination) {
		return malformed("geçersiz hedef adı")
	}
	if m.Sender != "" && !ValidBusName(m.Sender) {
		return malformed("geçersiz gönderen adı")
	}
	if m.UnixFDs > maxFDs {
		return malformed("çok fazla dosya tanımlayıcısı")
	}
	return nil
}

// marshal encodes the message (little endian, protocol version 1).
func (m *Message) marshal() ([]byte, error) { return m.marshalFDs(false) }

// marshalFDs encodes the message; withFDs keeps the UNIX_FDS field (the
// descriptors themselves travel beside the bytes; tests only).
func (m *Message) marshalFDs(withFDs bool) ([]byte, error) {
	if !withFDs && (m.UnixFDs != 0 || len(m.Files) != 0) {
		return nil, fmt.Errorf("%w: dosya tanımlayıcısı gönderilmez", ErrValue)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValue, err)
	}
	body, err := encodeBody(m.Signature, m.Body)
	if err != nil {
		return nil, err
	}
	var fields []any
	add := func(code byte, sig Signature, v any) {
		fields = append(fields, Struct{code, Variant{Sig: sig, Value: v}})
	}
	if m.Path != "" {
		add(fieldPath, "o", m.Path)
	}
	if m.Interface != "" {
		add(fieldInterface, "s", m.Interface)
	}
	if m.Member != "" {
		add(fieldMember, "s", m.Member)
	}
	if m.ErrorName != "" {
		add(fieldErrorName, "s", m.ErrorName)
	}
	if m.ReplySerial != 0 {
		add(fieldReplySerial, "u", m.ReplySerial)
	}
	if m.Destination != "" {
		add(fieldDestination, "s", m.Destination)
	}
	if m.Sender != "" {
		add(fieldSender, "s", m.Sender)
	}
	if withFDs && m.UnixFDs != 0 {
		add(fieldUnixFDs, "u", m.UnixFDs)
	}
	if m.Signature != "" {
		add(fieldSignature, "g", m.Signature)
	}
	e := &encoder{buf: make([]byte, 0, 128+len(body))}
	e.u8('l')
	e.u8(byte(m.Type))
	e.u8(m.Flags)
	e.u8(1)
	e.u32(uint32(len(body)))
	e.u32(m.Serial)
	if err := e.value("a(yv)", fields, 0); err != nil {
		return nil, err
	}
	e.align(8)
	e.buf = append(e.buf, body...)
	if len(e.buf) > MaxMessageSize {
		return nil, ErrTooLarge
	}
	return e.buf, nil
}

// readMessage reads one message from r. It never reads more than the
// message's own bytes and refuses anything larger than MaxMessageSize
// before allocating for it.
func readMessage(r io.Reader) (*Message, error) {
	var fixed [16]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch fixed[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		return nil, malformed("bilinmeyen bayt sırası")
	}
	if fixed[3] != 1 {
		return nil, malformed("protokol sürümü %d", fixed[3])
	}
	bodyLen := uint64(order.Uint32(fixed[4:8]))
	fieldsLen := uint64(order.Uint32(fixed[12:16]))
	headerLen := 16 + fieldsLen
	padded := (headerLen + 7) &^ 7
	total := padded + bodyLen
	if fieldsLen > MaxMessageSize || bodyLen > MaxMessageSize || total > MaxMessageSize {
		return nil, ErrTooLarge
	}
	buf := make([]byte, total)
	copy(buf, fixed[:])
	if _, err := io.ReadFull(r, buf[16:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return parseMessage(buf, order, int(headerLen), int(padded))
}

// parseMessage decodes a complete message buffer.
func parseMessage(buf []byte, order binary.ByteOrder, headerLen, padded int) (*Message, error) {
	m := &Message{
		Type:   MessageType(buf[1]),
		Flags:  buf[2],
		Serial: order.Uint32(buf[8:12]),
	}
	d := &decoder{b: buf[:headerLen], off: 12, order: order}
	raw, err := d.value("a(yv)", 0, 0, 0)
	if err != nil {
		return nil, err
	}
	if d.off != headerLen {
		return nil, malformed("başlık alanları uzunluğu")
	}
	for i := headerLen; i < padded; i++ {
		if buf[i] != 0 {
			return nil, malformed("başlık dolgusu sıfır değil")
		}
	}
	seen := map[byte]bool{}
	for _, f := range raw.([]any) {
		st := f.(Struct)
		code := st[0].(byte)
		v := st[1].(Variant)
		if seen[code] {
			return nil, malformed("yinelenen başlık alanı %d", code)
		}
		seen[code] = true
		if err := m.setField(code, v); err != nil {
			return nil, err
		}
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	body := buf[padded:]
	if len(body) > 0 && m.Signature == "" {
		return nil, malformed("imzasız gövde")
	}
	m.Body, err = decodeBody(body, order, m.Signature)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Message) setField(code byte, v Variant) error {
	want := map[byte]Signature{
		fieldPath: "o", fieldInterface: "s", fieldMember: "s", fieldErrorName: "s",
		fieldReplySerial: "u", fieldDestination: "s", fieldSender: "s", fieldSignature: "g", fieldUnixFDs: "u",
	}[code]
	if want == "" {
		return nil // unknown fields are ignored, as the specification says
	}
	if v.Sig != want {
		return malformed("başlık alanı %d türü %q", code, v.Sig)
	}
	switch code {
	case fieldPath:
		m.Path = v.Value.(ObjectPath)
	case fieldInterface:
		m.Interface = v.Value.(string)
	case fieldMember:
		m.Member = v.Value.(string)
	case fieldErrorName:
		m.ErrorName = v.Value.(string)
	case fieldReplySerial:
		m.ReplySerial = v.Value.(uint32)
	case fieldDestination:
		m.Destination = v.Value.(string)
	case fieldSender:
		m.Sender = v.Value.(string)
	case fieldSignature:
		m.Signature = v.Value.(Signature)
	case fieldUnixFDs:
		m.UnixFDs = v.Value.(uint32)
	}
	return nil
}
