package filesend

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// Document metadata removal before sending (#658, ADR-0205). Office Open
// XML (docx, xlsx, pptx) and OpenDocument (odt, ods, odp) files carry the
// author, the last editor, the company, the template and, in Word, the
// names on comments and tracked changes. PDF files carry the author, the
// creating program and the producer in the document information
// dictionary and in XMP.
//
// Office and OpenDocument files are zip archives: the text of the
// identifying elements and author attributes is emptied, every other
// entry is copied unchanged (compressed bytes are not touched). PDF text
// is overwritten in place with the same number of bytes, so cross
// reference offsets stay valid. Information inside compressed object
// streams (PDF 1.5 and later) cannot be reached this way; such a file is
// sent as cleaned as possible and ADR-0205 documents the limit.

// ErrDocumentTooLarge is returned for archives that expand beyond the
// limit while cleaning.
var ErrDocumentTooLarge = errors.New("belge üst veri temizlemek için çok büyük")

const maxDocPart = 64 << 20

var (
	officeExts = map[string]bool{".docx": true, ".docm": true, ".xlsx": true, ".xlsm": true, ".pptx": true, ".pptm": true,
		".odt": true, ".ods": true, ".odp": true}
	// Elements whose text identifies a person or an organisation.
	identElems = []string{
		"dc:creator", "cp:lastModifiedBy", "cp:lastPrinted", "cp:keywords", "dc:description", "cp:category",
		"Company", "Manager", "Template", "HyperlinkBase",
		"meta:initial-creator", "meta:printed-by", "meta:template",
	}
	identElemRes = func() []*regexp.Regexp {
		out := make([]*regexp.Regexp, 0, len(identElems))
		for _, e := range identElems {
			q := regexp.QuoteMeta(e)
			out = append(out, regexp.MustCompile(`(<`+q+`(?:\s[^>]*)?>)[^<]*(</`+q+`>)`))
		}
		return out
	}()
	// Attributes naming people in comments and tracked changes.
	authorAttrRe = regexp.MustCompile(`\b(w:author|w:initials|dc:creator|author)="[^"]*"`)
)

// StripDocumentMetadata removes identifying metadata from Office,
// OpenDocument and PDF files and returns other data unchanged.
func StripDocumentMetadata(name string, data []byte) ([]byte, error) {
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case officeExts[ext] && bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return stripOffice(data)
	case bytes.HasPrefix(data, []byte("%PDF-")):
		return stripPDF(data), nil
	}
	return data, nil
}

func officePartToClean(name string) bool {
	n := strings.ToLower(name)
	switch {
	case n == "docprops/core.xml", n == "docprops/app.xml", n == "meta.xml":
		return true
	case strings.HasPrefix(n, "word/") && strings.HasSuffix(n, ".xml"):
		return true
	case strings.HasPrefix(n, "xl/comments") || strings.HasPrefix(n, "xl/threadedcomments") || n == "xl/persons/person.xml":
		return true
	case strings.HasPrefix(n, "ppt/commentauthors") || strings.HasPrefix(n, "ppt/comments/"):
		return true
	}
	return false
}

func cleanXML(b []byte) []byte {
	for _, re := range identElemRes {
		b = re.ReplaceAll(b, []byte("$1$2"))
	}
	b = authorAttrRe.ReplaceAll(b, []byte(`$1=""`))
	// Excel persons and PowerPoint comment authors carry displayName.
	b = displayNameRe.ReplaceAll(b, []byte(`$1=""`))
	return b
}

var displayNameRe = regexp.MustCompile(`\b(displayName|name|userId)="[^"]*"`)

func stripOffice(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("belge arşivi okunamadı; üst veri temizlenemedi")
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	changed := false
	for _, f := range zr.File {
		if !officePartToClean(f.Name) || f.UncompressedSize64 > maxDocPart {
			if officePartToClean(f.Name) {
				return nil, ErrDocumentTooLarge
			}
			if err := zw.Copy(f); err != nil {
				return nil, err
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		part, err := io.ReadAll(io.LimitReader(rc, maxDocPart+1))
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		if len(part) > maxDocPart {
			return nil, ErrDocumentTooLarge
		}
		clean := part
		lower := strings.ToLower(f.Name)
		if lower == "docprops/core.xml" || lower == "docprops/app.xml" || lower == "meta.xml" {
			clean = cleanXML(part)
		} else {
			// Body parts: only author attributes, not displayName/name,
			// which are ordinary content there.
			clean = authorAttrRe.ReplaceAll(part, []byte(`$1=""`))
			if strings.Contains(lower, "person") || strings.Contains(lower, "commentauthor") {
				clean = cleanXML(part)
			}
		}
		if !bytes.Equal(clean, part) {
			changed = true
		}
		hdr := f.FileHeader
		hdr.CompressedSize64, hdr.UncompressedSize64, hdr.CRC32 = 0, 0, 0
		if hdr.Method != zip.Store {
			hdr.Method = zip.Deflate
		}
		w, err := zw.CreateHeader(&hdr)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(clean); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if !changed {
		return data, nil
	}
	return out.Bytes(), nil
}

var pdfInfoKeys = [][]byte{[]byte("/Author"), []byte("/Creator"), []byte("/Producer"), []byte("/Company"),
	[]byte("/Keywords"), []byte("/SourceModified")}

var xmpTags = []string{"dc:creator", "xmp:CreatorTool", "pdf:Producer", "pdf:Author", "xmpMM:DocumentID",
	"xmpMM:InstanceID", "photoshop:AuthorsPosition", "pdf:Keywords"}

// stripPDF blanks the values in place, keeping the file length.
func stripPDF(data []byte) []byte {
	out := bytes.Clone(data)
	for _, key := range pdfInfoKeys {
		for i := 0; ; {
			j := bytes.Index(out[i:], key)
			if j < 0 {
				break
			}
			p := i + j + len(key)
			i = p
			// Key must end here (not /CreatorTool and so on).
			if p < len(out) && isPDFNameChar(out[p]) {
				continue
			}
			for p < len(out) && isPDFSpace(out[p]) {
				p++
			}
			if p >= len(out) {
				break
			}
			switch out[p] {
			case '(':
				blankLiteral(out, p)
			case '<':
				if p+1 < len(out) && out[p+1] != '<' {
					blankHex(out, p)
				}
			}
		}
	}
	for _, tag := range xmpTags {
		open := []byte("<" + tag)
		closeTag := []byte("</" + tag + ">")
		for i := 0; ; {
			j := bytes.Index(out[i:], open)
			if j < 0 {
				break
			}
			start := i + j + len(open)
			gt := bytes.IndexByte(out[start:], '>')
			if gt < 0 {
				break
			}
			if start < len(out) && out[start] != '>' && !isPDFSpace(out[start]) {
				i = start
				continue
			}
			contentStart := start + gt + 1
			end := bytes.Index(out[contentStart:], closeTag)
			if end < 0 || end > 1<<16 {
				i = contentStart
				continue
			}
			blankXMLText(out[contentStart : contentStart+end])
			i = contentStart + end
		}
	}
	return out
}

func isPDFSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == 0
}

func isPDFNameChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'
}

// blankLiteral replaces the inside of a literal string at out[p] == '('
// with spaces, honouring nesting and escapes.
func blankLiteral(out []byte, p int) {
	depth := 0
	for k := p; k < len(out) && k-p < 1<<16; k++ {
		switch out[k] {
		case '\\':
			if k > p {
				out[k] = ' '
				if k+1 < len(out) {
					k++
					out[k] = ' '
				}
			}
			continue
		case '(':
			depth++
			if depth == 1 {
				continue
			}
		case ')':
			depth--
			if depth == 0 {
				return
			}
		}
		if depth >= 1 {
			out[k] = ' '
		}
	}
}

// blankHex replaces the digits of a hex string with "20" pairs (spaces).
func blankHex(out []byte, p int) {
	n := 0
	for k := p + 1; k < len(out) && out[k] != '>' && k-p < 1<<16; k++ {
		c := out[k]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			if n%2 == 0 {
				out[k] = '2'
			} else {
				out[k] = '0'
			}
			n++
		}
	}
}

// blankXMLText blanks character data but keeps nested tags (rdf:li).
func blankXMLText(b []byte) {
	inTag := false
	for k, c := range b {
		switch {
		case c == '<':
			inTag = true
		case c == '>':
			inTag = false
		case !inTag && !isPDFSpace(c):
			b[k] = ' '
		}
	}
}
