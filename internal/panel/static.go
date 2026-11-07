package panel

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"golang.org/x/net/html"
)

// maxStaticFile bounds a single embedded or on-disk panel file.
const maxStaticFile = 16 << 20

// site serves the exported panel and precomputes a CSP per HTML page that
// allows exactly the inline scripts Next.js emitted, by SHA-256 hash.
type site struct {
	files fs.FS
	csp   map[string]string
	built bool
}

const baseCSP = "default-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func newSite(files fs.FS) (*site, error) {
	s := &site{files: files, csp: map[string]string{}}
	err := fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		data, err := readFile(files, p)
		if err != nil {
			return err
		}
		hashes, err := inlineScriptHashes(data)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		s.csp[p] = pageCSP(hashes)
		if p == "index.html" {
			s.built = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// pageCSP builds the policy for a page. 'unsafe-inline' is never allowed
// for scripts; only the hashed inline scripts and same-origin files run.
func pageCSP(hashes []string) string {
	script := "script-src 'self'"
	for _, h := range hashes {
		script += " 'sha256-" + h + "'"
	}
	return baseCSP + "; " + script
}

// inlineScriptHashes returns the base64 SHA-256 of every inline <script>
// body, exactly as the browser will hash it.
func inlineScriptHashes(page []byte) ([]string, error) {
	z := html.NewTokenizer(bytes.NewReader(page))
	var hashes []string
	inScript := false
	var body bytes.Buffer
	for {
		switch z.Next() {
		case html.ErrorToken:
			if errors.Is(z.Err(), io.EOF) {
				return hashes, nil
			}
			return nil, z.Err()
		case html.StartTagToken:
			name, hasAttr := z.TagName()
			if string(name) != "script" {
				continue
			}
			inScript = !hasSrc(z, hasAttr)
			body.Reset()
		case html.TextToken:
			if inScript {
				body.Write(z.Raw())
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == "script" && inScript {
				sum := sha256.Sum256(body.Bytes())
				hashes = append(hashes, base64.StdEncoding.EncodeToString(sum[:]))
				inScript = false
			}
		}
	}
}

func hasSrc(z *html.Tokenizer, hasAttr bool) bool {
	for hasAttr {
		var key []byte
		key, _, hasAttr = z.TagAttr()
		if string(key) == "src" {
			return true
		}
	}
	return false
}

// resolve maps a URL path to a file in the export. It never escapes the
// export root: the path is cleaned and fs.FS rejects "..".
func (s *site) resolve(urlPath string) (string, bool) {
	clean := strings.TrimPrefix(path.Clean("/"+urlPath), "/")
	candidates := []string{clean}
	if clean == "" || clean == "." {
		candidates = []string{"index.html"}
	} else if path.Ext(clean) == "" {
		candidates = []string{clean + "/index.html", clean + ".html"}
	} else if alt, ok := segmentPrefetchPath(clean); ok {
		candidates = append(candidates, alt)
	}
	for _, c := range candidates {
		if !fs.ValidPath(c) {
			return "", false
		}
		if info, err := fs.Stat(s.files, c); err == nil && info.Mode().IsRegular() {
			return c, true
		}
	}
	return "", false
}

// segmentPrefetchPath maps the URL Next.js uses to prefetch a route
// segment ("cihazlar/__next.cihazlar.__PAGE__.txt") to the file the static
// export writes ("cihazlar/__next.cihazlar/__PAGE__.txt").
func segmentPrefetchPath(name string) (string, bool) {
	dir, base := path.Split(name)
	if !strings.HasPrefix(base, "__next.") || !strings.HasSuffix(base, ".txt") {
		return "", false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(base, "__next."), ".txt"), ".")
	if len(parts) < 2 {
		return "", false
	}
	return dir + "__next." + parts[0] + "/" + strings.Join(parts[1:], "/") + ".txt", true
}

func (s *site) serve(w http.ResponseWriter, r *http.Request, name string, status int) {
	data, err := readFile(s.files, name)
	if err != nil {
		http.Error(w, "Dosya okunamadı", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		h.Set("Content-Type", ct)
	} else {
		h.Set("Content-Type", "application/octet-stream")
	}
	if strings.HasSuffix(name, ".html") {
		h.Set("Content-Security-Policy", s.csp[name])
		h.Set("Content-Security-Policy-Report-Only", trustedTypesReportOnly) // #519, p11_api.go
		h.Set("Cache-Control", "no-store")
	} else if strings.HasPrefix(name, "_next/static/") {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func readFile(files fs.FS, name string) ([]byte, error) {
	f, err := files.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStaticFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxStaticFile {
		return nil, errors.New("static file is too large")
	}
	return data, nil
}
