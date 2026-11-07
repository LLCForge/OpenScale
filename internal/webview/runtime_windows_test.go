//go:build windows

package webview

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestFindRuntimeReadOnly reads the real registry (nothing is written).
// A computer without WebView2 is not a failure: Open then returns
// ErrUnavailable and the caller uses the browser.
func TestFindRuntimeReadOnly(t *testing.T) {
	rt, err := findRuntime()
	if err != nil {
		t.Skipf("WebView2 çalışma zamanı yok: %v", err)
	}
	if rt.version[0] < minRuntimeMajor || filepath.Base(rt.dll) != "EmbeddedBrowserWebView.dll" ||
		filepath.Base(filepath.Dir(rt.dll)) != archDir(runtime.GOARCH) {
		t.Fatalf("beklenmeyen çalışma zamanı: %+v", rt)
	}
	t.Logf("WebView2 %s: %s", rt.version, rt.dll)
}

func TestHandlerQueryInterface(t *testing.T) {
	iid := mustGUID("{9ADBE429-F36D-432B-9DDC-F8881FBD76E3}")
	called := 0
	h, err := newHandler(iid, func(a, b uintptr) uintptr { called++; return uintptr(a + b) })
	if err != nil {
		t.Fatal(err)
	}
	if q, err := h.queryInterface(&iid); err != nil || q != h {
		t.Fatalf("kendi IID: %v %v", q, err)
	} else {
		q.release()
	}
	if q, err := h.queryInterface(&iidIUnknown); err != nil || q != h {
		t.Fatalf("IUnknown: %v %v", q, err)
	} else {
		q.release()
	}
	other := mustGUID("{00000003-0000-0000-C000-000000000046}") // IMarshal
	if _, err := h.queryInterface(&other); err == nil {
		t.Fatal("bilinmeyen arayüz kabul edildi")
	}
	if r := h.call(3, 2, 3); r != 5 || called != 1 {
		t.Fatalf("Invoke = %d, çağrı %d", r, called)
	}
	h.release()
	handlersMu.Lock()
	n := len(handlers)
	handlersMu.Unlock()
	if n != 0 {
		t.Fatalf("serbest bırakılmayan işleyici: %d", n)
	}
}

func TestEnvironmentOptionsObject(t *testing.T) {
	o, err := newEnvironmentOptions("--proxy-server=http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer o.release()
	if s, err := o.getString(3); err != nil || s != "--proxy-server=http://127.0.0.1:1" {
		t.Fatalf("AdditionalBrowserArguments = %q, %v", s, err)
	}
	if s, err := o.getString(7); err != nil || s != targetCompatibleVersion {
		t.Fatalf("TargetCompatibleBrowserVersion = %q, %v", s, err)
	}
	if b, err := o.getBool(9); err != nil || b {
		t.Fatalf("AllowSingleSignOnUsingOSPrimaryAccount = %v, %v", b, err)
	}
	if err := o.putBool(4, true); err == nil {
		t.Fatal("put_* kabul edilmemeli")
	}
}
