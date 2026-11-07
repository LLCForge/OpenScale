package dnssec

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// rootAnchors are the root zone key-signing keys as DS records, from
// IANA's root-anchors.xml (checked 2026-10-30): KSK-2017 (tag 20326,
// valid from 2017-02-02) and KSK-2024 (tag 38696, valid from 2024-07-18,
// the successor in IANA's planned 2026 rollover). Both are trusted so
// validation works on either side of the rollover; ParseAnchors lets the
// owner replace them after a later rollover without a new build. They are digests,
// not addresses: nothing is contacted because of them (ADR-0008).
var rootAnchors = []struct {
	tag    uint16
	digest string
}{
	{20326, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"},
	{38696, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"},
}

// RootAnchors returns the built-in trust anchors of the root zone.
func RootAnchors() []DS {
	out := make([]DS, 0, len(rootAnchors))
	for _, a := range rootAnchors {
		d, err := hex.DecodeString(a.digest)
		if err != nil {
			panic("dnssec: bad built-in anchor") // a literal above; tested
		}
		out = append(out, DS{KeyTag: a.tag, Algorithm: AlgRSASHA256, DigestType: DigestSHA256, Digest: d})
	}
	return out
}

// Limits of an owner-supplied anchor file.
const (
	maxAnchorLines = 64
	maxAnchorLine  = 1024
)

// ParseAnchors reads root trust anchors the owner supplies, one DS record
// per line in zone file form: ". [TTL] [IN] DS <tag> <alg> <digest type>
// <hex digest>". Empty lines and lines starting with ';' or '#' are
// skipped. Only the root (".") is accepted. At least one anchor with a
// supported algorithm and digest is required.
func ParseAnchors(r io.Reader) ([]DS, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxAnchorLines*maxAnchorLine))
	sc.Buffer(make([]byte, 0, maxAnchorLine), maxAnchorLine)
	var out []DS
	supported := false
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "#") {
			continue
		}
		f := strings.Fields(s)
		if len(f) < 6 || f[0] != "." {
			return nil, fmt.Errorf("güven çapası satır %d: \". DS etiket algoritma özet-türü özet\" bekleniyor", line)
		}
		f = f[1:]
		if _, err := strconv.ParseUint(f[0], 10, 32); err == nil {
			f = f[1:] // TTL
		}
		if len(f) > 0 && strings.EqualFold(f[0], "IN") {
			f = f[1:]
		}
		if len(f) < 5 || !strings.EqualFold(f[0], "DS") {
			return nil, fmt.Errorf("güven çapası satır %d: DS kaydı değil", line)
		}
		tag, err1 := strconv.ParseUint(f[1], 10, 16)
		alg, err2 := strconv.ParseUint(f[2], 10, 8)
		dt, err3 := strconv.ParseUint(f[3], 10, 8)
		digest, err4 := hex.DecodeString(strings.Join(f[4:], ""))
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			return nil, fmt.Errorf("güven çapası satır %d: %w", line, err)
		}
		rdata := DS{KeyTag: uint16(tag), Algorithm: uint8(alg), DigestType: uint8(dt), Digest: digest}.Rdata()
		d, err := ParseDS(rdata)
		if err != nil {
			return nil, fmt.Errorf("güven çapası satır %d: özet uzunluğu geçersiz", line)
		}
		supported = supported || d.Supported()
		out = append(out, d)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("güven çapası dosyası okunamadı: %w", err)
	}
	if !supported {
		return nil, errors.New("güven çapası dosyasında desteklenen algoritma ve özetle bir DS kaydı yok")
	}
	return out, nil
}
