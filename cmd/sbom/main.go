// Command sbom writes a minimal SPDX 2.3 JSON bill of materials for an
// OpenScale release (#211). It reads only local files:
//
//   - the build information of each Go binary: either the binary itself or
//     the text output of `go version -m BINARY`;
//   - panel/pnpm-lock.yaml, from which the production dependency closure of
//     the embedded panel is taken (development tools are not shipped).
//
// Output is deterministic: the creation time comes from SOURCE_DATE_EPOCH
// and every list is sorted.
//
//	go run ./cmd/sbom -version 0.9.0 -source-date-epoch N -panel-lock panel/pnpm-lock.yaml \
//	    -out dist/openscale-0.9.0.spdx.json bin/openscale-linux-amd64 ...
package main

import (
	"bufio"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"time"
)

const (
	maxInputSize   = 64 << 20
	maxModinfoSize = 4 << 20
	noAssertion    = "NOASSERTION"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	version := fs.String("version", "", "OpenScale sürümü")
	sde := fs.Int64("source-date-epoch", -1, "SOURCE_DATE_EPOCH (oluşturma zamanı)")
	lock := fs.String("panel-lock", "", "panel/pnpm-lock.yaml (isteğe bağlı)")
	out := fs.String("out", "", "çıktı dosyası (varsayılan: standart çıktı)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" || *sde < 0 || fs.NArg() == 0 {
		return errors.New("-version, -source-date-epoch ve en az bir ikili veya `go version -m` çıktısı gerekli")
	}
	var infos []binaryInfo
	for _, p := range fs.Args() {
		bi, err := readBuildInfo(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		infos = append(infos, binaryInfo{name: baseName(p), info: bi})
	}
	var npm []npmPackage
	if *lock != "" {
		data, err := readLimited(*lock, maxInputSize)
		if err != nil {
			return err
		}
		if npm, err = parsePnpmLock(string(data)); err != nil {
			return fmt.Errorf("%s: %w", *lock, err)
		}
	}
	doc := buildDocument(*version, time.Unix(*sde, 0).UTC(), infos, npm)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *out == "" {
		_, err = stdout.Write(data)
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}

type binaryInfo struct {
	name string
	info *debug.BuildInfo
}

// readBuildInfo reads a Go binary, or the output of `go version -m`.
func readBuildInfo(path string) (*debug.BuildInfo, error) {
	if bi, err := buildinfo.ReadFile(path); err == nil {
		return bi, nil
	}
	data, err := readLimited(path, maxModinfoSize)
	if err != nil {
		return nil, err
	}
	return parseGoVersionM(string(data))
}

// parseGoVersionM converts `go version -m` output ("FILE: go1.x" followed by
// tab-indented lines) to the format of debug.BuildInfo.String and parses it.
func parseGoVersionM(text string) (*debug.BuildInfo, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) < 2 {
		return nil, errors.New("not the output of `go version -m`")
	}
	first := lines[0]
	i := strings.LastIndex(first, ": ")
	if i < 0 || !strings.HasPrefix(first[i+2:], "go") {
		return nil, errors.New("not the output of `go version -m`")
	}
	var b strings.Builder
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "\t") {
			return nil, errors.New("output of more than one binary; give one file per binary")
		}
		b.WriteString(strings.TrimPrefix(l, "\t") + "\n")
	}
	bi, err := debug.ParseBuildInfo(b.String())
	if err != nil {
		return nil, err
	}
	// ParseBuildInfo does not restore the toolchain version.
	bi.GoVersion = strings.TrimSpace(first[i+2:])
	return bi, nil
}

// npmPackage is one package of the panel's production closure.
type npmPackage struct {
	Name, Version, Integrity string
}

// parsePnpmLock reads a pnpm v9 lockfile and returns the transitive closure
// of the importers' dependencies and optionalDependencies. It understands
// the subset of YAML that pnpm writes, not YAML in general.
func parsePnpmLock(text string) ([]npmPackage, error) {
	var (
		section, importerGroup, snapKey, snapGroup, pkgKey, depName string
		roots                                                       []string
		snapshots                                                   = map[string][]string{}
		integrity                                                   = map[string]string{}
	)
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	sawVersion := false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		body := strings.TrimSpace(line)
		if indent == 0 {
			section = strings.TrimSuffix(body, ":")
			if strings.HasPrefix(body, "lockfileVersion:") {
				v := unquote(strings.TrimSpace(strings.TrimPrefix(body, "lockfileVersion:")))
				if !strings.HasPrefix(v, "9.") {
					return nil, fmt.Errorf("unsupported pnpm lockfile version %q", v)
				}
				sawVersion = true
			}
			continue
		}
		key, value := splitKV(body)
		switch section {
		case "importers":
			switch indent {
			case 2:
				importerGroup = ""
			case 4:
				importerGroup = key
			case 6:
				depName = key
			case 8:
				if key == "version" && (importerGroup == "dependencies" || importerGroup == "optionalDependencies") {
					roots = append(roots, depName+"@"+unquote(value))
				}
			}
		case "snapshots":
			switch indent {
			case 2:
				snapKey, snapGroup = key, ""
				if _, ok := snapshots[snapKey]; !ok {
					snapshots[snapKey] = nil
				}
			case 4:
				snapGroup = key
			case 6:
				if snapGroup == "dependencies" || snapGroup == "optionalDependencies" {
					snapshots[snapKey] = append(snapshots[snapKey], key+"@"+unquote(value))
				}
			}
		case "packages":
			switch indent {
			case 2:
				pkgKey = key
			case 4:
				if key == "resolution" {
					if _, rest, ok := strings.Cut(value, "integrity:"); ok {
						v, _, _ := strings.Cut(strings.TrimSpace(rest), ",")
						integrity[pkgKey] = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "}"))
					}
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !sawVersion {
		return nil, errors.New("lockfileVersion missing")
	}

	seen := map[string]bool{}
	queue := slices.Clone(roots)
	pkgs := map[string]npmPackage{}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		if seen[k] {
			continue
		}
		seen[k] = true
		base := stripPeers(k)
		name, ver, ok := splitNameVersion(base)
		if !ok || strings.HasPrefix(ver, "link:") || strings.HasPrefix(ver, "file:") {
			continue
		}
		pkgs[base] = npmPackage{Name: name, Version: ver, Integrity: integrity[base]}
		queue = append(queue, snapshots[k]...)
	}
	out := make([]npmPackage, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b npmPackage) int {
		return strings.Compare(a.Name+"@"+a.Version, b.Name+"@"+b.Version)
	})
	return out, nil
}

// stripPeers turns "react-dom@19.3.0(react@19.3.0)" into "react-dom@19.3.0".
func stripPeers(k string) string {
	start := 1 // a scoped name starts with '@'
	at := strings.Index(k[min(start, len(k)):], "@")
	if at < 0 {
		return k
	}
	at += start
	if p := strings.IndexByte(k[at:], '('); p >= 0 {
		return k[:at+p]
	}
	return k
}

func splitNameVersion(k string) (string, string, bool) {
	if len(k) < 3 {
		return "", "", false
	}
	at := strings.LastIndex(k[1:], "@")
	if at < 0 {
		return "", "", false
	}
	at++
	return k[:at], k[at+1:], k[at+1:] != ""
}

// splitKV splits "key: value", where key may be quoted and contain ':'.
func splitKV(body string) (string, string) {
	if len(body) > 0 && (body[0] == '\'' || body[0] == '"') {
		if end := strings.IndexByte(body[1:], body[0]); end >= 0 {
			key := body[1 : end+1]
			rest := strings.TrimSpace(body[end+2:])
			return key, strings.TrimSpace(strings.TrimPrefix(rest, ":"))
		}
	}
	key, value, _ := strings.Cut(body, ":")
	return unquote(strings.TrimSpace(key)), strings.TrimSpace(value)
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' && s[len(s)-1] == '\'' || s[0] == '"' && s[len(s)-1] == '"') {
		return s[1 : len(s)-1]
	}
	return s
}

// SPDX 2.3 JSON subset.
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
	Comment          string            `json:"comment,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

func buildDocument(version string, created time.Time, bins []binaryInfo, npm []npmPackage) spdxDocument {
	ids := map[string]bool{}
	newID := func(s string) string {
		id := "SPDXRef-" + sanitizeID(s)
		for n := 2; ids[id]; n++ {
			id = fmt.Sprintf("SPDXRef-%s-%d", sanitizeID(s), n)
		}
		ids[id] = true
		return id
	}
	rootID := newID("openscale")
	var binNames, goVersions []string
	type goMod struct{ path, version, sum string }
	mods := map[string]goMod{}
	for _, b := range bins {
		target := setting(b.info, "GOOS") + "/" + setting(b.info, "GOARCH")
		if arm := setting(b.info, "GOARM"); arm != "" {
			target += "/v" + arm
		}
		binNames = append(binNames, b.name+" ("+target+")")
		if !slices.Contains(goVersions, b.info.GoVersion) {
			goVersions = append(goVersions, b.info.GoVersion)
		}
		for _, d := range b.info.Deps {
			m := d
			if d.Replace != nil {
				m = d.Replace
			}
			mods[m.Path+"@"+m.Version] = goMod{m.Path, m.Version, m.Sum}
		}
	}
	slices.Sort(binNames)
	slices.Sort(goVersions)

	doc := spdxDocument{
		SPDXVersion:  "SPDX-2.3",
		DataLicense:  "CC0-1.0",
		SPDXID:       "SPDXRef-DOCUMENT",
		Name:         "openscale-" + version,
		CreationInfo: spdxCreationInfo{Created: created.Format(time.RFC3339), Creators: []string{"Tool: openscale-tools-sbom"}},
	}
	doc.Packages = append(doc.Packages, spdxPackage{
		Name: "openscale", SPDXID: rootID, VersionInfo: version,
		DownloadLocation: noAssertion, LicenseConcluded: noAssertion, LicenseDeclared: noAssertion, CopyrightText: noAssertion,
		Comment: "Binaries: " + strings.Join(binNames, ", "),
	})
	doc.DocumentDescribes = []string{rootID}
	rel := func(a, typ, b string) {
		doc.Relationships = append(doc.Relationships, spdxRelationship{a, typ, b})
	}
	rel("SPDXRef-DOCUMENT", "DESCRIBES", rootID)

	for _, gv := range goVersions {
		id := newID("go-stdlib-" + gv)
		doc.Packages = append(doc.Packages, spdxPackage{
			Name: "stdlib", SPDXID: id, VersionInfo: gv,
			DownloadLocation: noAssertion, LicenseConcluded: noAssertion, LicenseDeclared: noAssertion, CopyrightText: noAssertion,
			ExternalRefs: []spdxExternalRef{{"PACKAGE-MANAGER", "purl", "pkg:golang/stdlib@" + strings.TrimPrefix(gv, "go")}},
		})
		rel(rootID, "DEPENDS_ON", id)
	}
	keys := make([]string, 0, len(mods))
	for k := range mods {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		m := mods[k]
		id := newID("go-" + m.path + "-" + m.version)
		p := spdxPackage{
			Name: m.path, SPDXID: id, VersionInfo: m.version,
			DownloadLocation: noAssertion, LicenseConcluded: noAssertion, LicenseDeclared: noAssertion, CopyrightText: noAssertion,
			ExternalRefs: []spdxExternalRef{{"PACKAGE-MANAGER", "purl", "pkg:golang/" + m.path + "@" + m.version}},
		}
		if m.sum != "" {
			p.Comment = "go.sum " + m.sum
		}
		doc.Packages = append(doc.Packages, p)
		rel(rootID, "DEPENDS_ON", id)
	}

	if len(npm) > 0 {
		panelID := newID("openscale-panel")
		doc.Packages = append(doc.Packages, spdxPackage{
			Name: "openscale-panel", SPDXID: panelID, VersionInfo: version,
			DownloadLocation: noAssertion, LicenseConcluded: noAssertion, LicenseDeclared: noAssertion, CopyrightText: noAssertion,
			Comment: "Static web panel embedded in the binary; production dependency closure from pnpm-lock.yaml.",
		})
		rel(rootID, "CONTAINS", panelID)
		for _, n := range npm {
			id := newID("npm-" + n.Name + "-" + n.Version)
			p := spdxPackage{
				Name: n.Name, SPDXID: id, VersionInfo: n.Version,
				DownloadLocation: noAssertion, LicenseConcluded: noAssertion, LicenseDeclared: noAssertion, CopyrightText: noAssertion,
				ExternalRefs: []spdxExternalRef{{"PACKAGE-MANAGER", "purl", npmPurl(n.Name, n.Version)}},
			}
			if c, ok := integrityChecksum(n.Integrity); ok {
				p.Checksums = []spdxChecksum{c}
			}
			doc.Packages = append(doc.Packages, p)
			rel(panelID, "DEPENDS_ON", id)
		}
	}

	// The namespace is derived from the content, so the same inputs always
	// give the same document and no external domain is needed.
	h := sha256.New()
	for _, p := range doc.Packages {
		fmt.Fprintf(h, "%s@%s\n", p.Name, p.VersionInfo)
	}
	doc.DocumentNamespace = "urn:openscale:sbom:" + version + ":" + hex.EncodeToString(h.Sum(nil))[:32]
	return doc
}

func setting(bi *debug.BuildInfo, key string) string {
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

func npmPurl(name, version string) string {
	if strings.HasPrefix(name, "@") {
		name = "%40" + strings.TrimPrefix(name, "@")
	}
	return "pkg:npm/" + name + "@" + version
}

// integrityChecksum converts an npm Subresource Integrity value.
func integrityChecksum(sri string) (spdxChecksum, bool) {
	algo, b64, ok := strings.Cut(sri, "-")
	if !ok {
		return spdxChecksum{}, false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return spdxChecksum{}, false
	}
	switch algo {
	case "sha512":
		return spdxChecksum{"SHA512", hex.EncodeToString(raw)}, len(raw) == 64
	case "sha256":
		return spdxChecksum{"SHA256", hex.EncodeToString(raw)}, len(raw) == 32
	case "sha1":
		return spdxChecksum{"SHA1", hex.EncodeToString(raw)}, len(raw) == 20
	}
	return spdxChecksum{}, false
}

// sanitizeID keeps the characters SPDX allows in identifiers.
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(p, ".modinfo")
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return data, nil
}
