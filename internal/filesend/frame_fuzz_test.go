package filesend

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzReadOffer covers the receiver's first frame (#654, ADR-0209): the
// length-prefixed JSON offer from any member, then name sanitizing.
func FuzzReadOffer(f *testing.F) {
	frame := func(s string) []byte {
		return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
	}
	f.Add(frame(`{"v":1,"name":"a.txt","size":3,"sha256":"00"}`))
	f.Add(frame(`{"v":1,"name":"../../etc/passwd","size":-1}`))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		var o offer
		if err := readFrame(bytes.NewReader(b), &o); err != nil {
			return
		}
		name, err := SanitizeName(o.Name)
		if err != nil {
			return
		}
		if bytes.ContainsAny([]byte(name), "/\\") || name == "." || name == ".." {
			t.Fatalf("unsafe name %q", name)
		}
	})
}
