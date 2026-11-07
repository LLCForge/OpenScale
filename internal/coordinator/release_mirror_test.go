package coordinator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/control"
)

func TestMirrorFileAllowlist(t *testing.T) {
	for _, ok := range []string{"openscale-1.0.0.release.json", "openscale-1.0.0-beta.2.release.json", "revocations.json",
		"openscale-linux-arm64.gz", "openscale-windows-amd64.exe.gz", "openscale_1.0.0~beta.2_armhf.deb"} {
		if _, allowed := MirrorFileAllowed(ok); !allowed {
			t.Errorf("refused %s", ok)
		}
	}
	for _, bad := range []string{"../coordinator.key", "coordinator.key", "network.json", "openscale-linux-amd64", "openscale_1_i386.deb",
		".publish-1.tmp", "openscale-x.release.json/..", "release-source.json"} {
		if _, allowed := MirrorFileAllowed(bad); allowed {
			t.Errorf("allowed %s", bad)
		}
	}
}

func TestMirrorServesOnlyItsFiles(t *testing.T) {
	state := t.TempDir()
	mirror := filepath.Join(state, ReleaseMirrorDir)
	if err := os.MkdirAll(mirror, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(mirror, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A secret next to the mirror, a file in it outside the allowlist.
	if err := os.WriteFile(filepath.Join(state, "coordinator.key"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	write("notes.txt", "x")
	h, reload := ReleaseMirrorHandler(mirror, nil)
	if a := h(control.Message{T: control.TypeRelease}); a.T != control.TypeRelease || a.Release != "" {
		t.Fatalf("nothing published: %+v", a)
	}
	write("openscale-2.0.0.release.json", "manifest")
	write("openscale-linux-amd64.gz", strings.Repeat("p", 2000))
	reload()
	a := h(control.Message{T: control.TypeRelease})
	if a.Release != "2.0.0" || a.Size != len("manifest") {
		t.Fatalf("%+v", a)
	}
	for _, name := range []string{"../coordinator.key", "coordinator.key", "notes.txt", "openscale-linux-arm64.gz"} {
		if r := h(control.Message{T: control.TypeReleaseFile, File: name, Digest: a.Digest}); r.T != control.TypeError {
			t.Errorf("%s served: %+v", name, r)
		}
	}
	r := h(control.Message{T: control.TypeReleaseFile, File: "openscale-linux-amd64.gz", Digest: a.Digest, Offset: control.ChunkSize * 2})
	if r.T != control.TypeReleaseFile || r.Total != 2000 || len(r.Data) != 2000-2*control.ChunkSize {
		t.Fatalf("last chunk %+v", r)
	}
	if r := h(control.Message{T: control.TypeReleaseFile, File: "openscale-linux-amd64.gz", Digest: a.Digest, Offset: 2001}); r.T != control.TypeError {
		t.Fatal("offset past the end")
	}
	// Two manifests: nothing is announced.
	write("openscale-2.0.1.release.json", "other")
	reload()
	if a := h(control.Message{T: control.TypeRelease}); a.Release != "" {
		t.Fatalf("ambiguous mirror announced %+v", a)
	}
	// An oversized or non-regular file stops the whole mirror (fail closed).
	_ = os.Remove(filepath.Join(mirror, "openscale-2.0.1.release.json"))
	if err := os.Mkdir(filepath.Join(mirror, "revocations.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	reload()
	if a := h(control.Message{T: control.TypeRelease}); a.Release != "" {
		t.Fatalf("mirror with a directory entry announced %+v", a)
	}
}
