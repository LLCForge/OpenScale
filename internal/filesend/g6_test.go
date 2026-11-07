package filesend

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func makeDocx(t *testing.T, parts map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, name := range []string{"[Content_Types].xml", "docProps/core.xml", "docProps/app.xml", "word/document.xml", "word/media/image1.png"} {
		body, ok := parts[name]
		if !ok {
			continue
		}
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func readZipPart(t *testing.T, data []byte, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			return string(b)
		}
	}
	t.Fatalf("part %s missing", name)
	return ""
}

func TestStripOfficeMetadata(t *testing.T) {
	doc := makeDocx(t, map[string]string{
		"[Content_Types].xml":   `<Types/>`,
		"docProps/core.xml":     `<cp:coreProperties><dc:title>Teklif</dc:title><dc:creator>Ayşe Yılmaz</dc:creator><cp:lastModifiedBy>Mehmet Kaya</cp:lastModifiedBy></cp:coreProperties>`,
		"docProps/app.xml":      `<Properties><Company>Gizli A.Ş.</Company><Manager>Ali</Manager><Pages>2</Pages></Properties>`,
		"word/document.xml":     `<w:document><w:ins w:id="1" w:author="Mehmet Kaya" w:date="2026"><w:t>metin</w:t></w:ins></w:document>`,
		"word/media/image1.png": "PNGDATA",
	})
	out, err := StripDocumentMetadata("teklif.docx", doc)
	if err != nil {
		t.Fatal(err)
	}
	all := readZipPart(t, out, "docProps/core.xml") + readZipPart(t, out, "docProps/app.xml") + readZipPart(t, out, "word/document.xml")
	for _, leak := range []string{"Ayşe", "Mehmet", "Gizli", "Ali"} {
		if strings.Contains(all, leak) {
			t.Fatalf("%q survived: %s", leak, all)
		}
	}
	for _, keep := range []string{"Teklif", "<Pages>2</Pages>", "metin"} {
		if !strings.Contains(all, keep) {
			t.Fatalf("%q was removed", keep)
		}
	}
	if readZipPart(t, out, "word/media/image1.png") != "PNGDATA" {
		t.Fatal("media changed")
	}
	// A document without identifying data is returned unchanged.
	plain := makeDocx(t, map[string]string{"docProps/core.xml": `<cp:coreProperties><dc:title>x</dc:title></cp:coreProperties>`})
	if again, err := StripDocumentMetadata("x.docx", plain); err != nil || !bytes.Equal(again, plain) {
		t.Fatal("clean document was rewritten")
	}
}

func TestStripPDFMetadata(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj\n<< /Title (Rapor) /Author (Ay\\(se\\) (Yilmaz)) /Creator <4D6963726F736F6674> /Producer (PDFlib) /CreatorTool (keep) >>\nendobj\n" +
		"2 0 obj\n<< /Type /Metadata >>\nstream\n<x:xmpmeta><dc:creator><rdf:Seq><rdf:li>Ayse Yilmaz</rdf:li></rdf:Seq></dc:creator><xmp:CreatorTool>Word 2026</xmp:CreatorTool></x:xmpmeta>\nendstream\nendobj\n%%EOF\n")
	out, err := StripDocumentMetadata("r.pdf", pdf)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(pdf) {
		t.Fatalf("length changed %d -> %d", len(pdf), len(out))
	}
	s := string(out)
	for _, leak := range []string{"Yilmaz", "4D6963726F736F6674", "PDFlib", "Word 2026", "Ay\\(se"} {
		if strings.Contains(s, leak) {
			t.Fatalf("%q survived:\n%s", leak, s)
		}
	}
	if !strings.Contains(s, "(Rapor)") || !strings.Contains(s, "/CreatorTool (keep)") || !strings.Contains(s, "<rdf:li>") {
		t.Fatalf("too much removed:\n%s", s)
	}
}

func TestStripDocumentPassesOtherFiles(t *testing.T) {
	data := []byte("PK\x03\x04 not a document")
	if out, err := StripDocumentMetadata("a.zip", data); err != nil || !bytes.Equal(out, data) {
		t.Fatal("zip changed")
	}
	if _, err := StripDocumentMetadata("a.docx", data); err == nil {
		t.Fatal("broken docx accepted")
	}
}

func TestMarkQuarantine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gelen.txt")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := MarkQuarantine(p, "openscale:laptop;bad\\")
	switch runtime.GOOS {
	case "windows", "darwin":
		if err != nil {
			t.Fatalf("mark: %v", err)
		}
		if !IsQuarantined(p) {
			t.Fatal("mark not readable")
		}
	default:
		// tmpfs and some file systems refuse user xattrs; both are fine.
		if err == nil && !IsQuarantined(p) {
			t.Fatal("mark not readable")
		}
	}
	if got := cleanOrigin("a b;c\\d\"e"); got != "abcde" {
		t.Fatalf("cleanOrigin = %q", got)
	}
}

func FuzzStripDocumentMetadata(f *testing.F) {
	f.Add("a.pdf", []byte("%PDF-1.7 /Author (x(y)\\) /Producer <00>"))
	f.Add("a.docx", []byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		out, err := StripDocumentMetadata(name, data)
		if err == nil && bytes.HasPrefix(data, []byte("%PDF-")) && len(out) != len(data) {
			t.Fatal("pdf length changed")
		}
	})
}
