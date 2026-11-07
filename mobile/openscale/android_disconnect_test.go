package openscale

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Güvenlik denetimi bulgu 10 (F5): dışa açık MainActivity, başka bir
// uygulamanın REQUEST_DISCONNECT eylemiyle VPN tünelini kesmesine izin
// veriyordu. Android SDK bu makinede olmadığı için Kotlin derlenemez; bu
// test, düzeltmenin dayandığı değişmezleri kaynak ve manifest üzerinden
// denetler (JVM'siz):
//   - dışa kapalı bir .DisconnectRequest takma adı MainActivity'yi hedefler;
//   - kesme eylemi yalnızca DisconnectRequest.kt'de tanımlanır ve uygulama
//     içi çağıranlar niyeti yalnızca DisconnectRequest.intent ile kurar;
//   - MainActivity.handleIntent, kesmeden önce DisconnectRequest.accept ile
//     niyetin çözüldüğü bileşeni denetler;
//   - accept, eylem ve bileşen adını birlikte ister.

const androidSrc = "../android/app/src/main"

type manifestComponent struct {
	Name           string `xml:"http://schemas.android.com/apk/res/android name,attr"`
	Exported       string `xml:"http://schemas.android.com/apk/res/android exported,attr"`
	TargetActivity string `xml:"http://schemas.android.com/apk/res/android targetActivity,attr"`
	Permission     string `xml:"http://schemas.android.com/apk/res/android permission,attr"`
}

type androidManifest struct {
	Application struct {
		Activities []manifestComponent `xml:"activity"`
		Aliases    []manifestComponent `xml:"activity-alias"`
	} `xml:"application"`
}

func readAndroidFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(androidSrc, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("%s okunamadı: %v", rel, err)
	}
	return string(b)
}

func TestAndroidDisconnectRequestAliasNotExported(t *testing.T) {
	var m androidManifest
	if err := xml.Unmarshal([]byte(readAndroidFile(t, "AndroidManifest.xml")), &m); err != nil {
		t.Fatalf("manifest çözülemedi: %v", err)
	}
	var alias *manifestComponent
	for i := range m.Application.Aliases {
		if m.Application.Aliases[i].Name == ".DisconnectRequest" {
			alias = &m.Application.Aliases[i]
		}
	}
	if alias == nil {
		t.Fatal(".DisconnectRequest takma adı yok: kesme isteği dışa açık MainActivity'ye doğrudan gidiyor")
	}
	if alias.Exported != "false" {
		t.Fatalf(".DisconnectRequest exported=%q; \"false\" olmalı", alias.Exported)
	}
	if alias.TargetActivity != ".MainActivity" {
		t.Fatalf(".DisconnectRequest targetActivity=%q; \".MainActivity\" olmalı", alias.TargetActivity)
	}
}

func TestAndroidDisconnectActionOnlyViaAlias(t *testing.T) {
	dir := filepath.Join(androidSrc, "kotlin", "org", "openscale", "android")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("kotlin dizini okunamadı: %v", err)
	}
	literal := `"org.openscale.android.REQUEST_DISCONNECT"`
	// MainActivity::class.java hedefli bir niyete kesme eyleminin konması.
	direct := regexp.MustCompile(`MainActivity::class\.java\)[^\n]*ACTION_REQUEST_DISCONNECT`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".kt") {
			continue
		}
		src := readAndroidFile(t, "kotlin/org/openscale/android/"+e.Name())
		if strings.Contains(src, literal) && e.Name() != "DisconnectRequest.kt" {
			t.Errorf("%s kesme eylemini dizgi olarak tanımlıyor; yalnızca DisconnectRequest.ACTION kullanılmalı", e.Name())
		}
		if direct.MatchString(src) {
			t.Errorf("%s kesme isteğini dışa açık MainActivity'ye gönderiyor; DisconnectRequest.intent kullanılmalı", e.Name())
		}
		if e.Name() != "MainActivity.kt" && strings.Contains(src, "ACTION_REQUEST_DISCONNECT") {
			t.Errorf("%s ACTION_REQUEST_DISCONNECT kullanıyor; niyet DisconnectRequest.intent ile kurulmalı", e.Name())
		}
	}
}

func TestAndroidHandleIntentChecksComponent(t *testing.T) {
	src := readAndroidFile(t, "kotlin/org/openscale/android/MainActivity.kt")
	start := strings.Index(src, "private fun handleIntent(")
	if start < 0 {
		t.Fatal("MainActivity.handleIntent bulunamadı")
	}
	body := src[start:]
	if end := strings.Index(body, "\n    }\n"); end > 0 {
		body = body[:end]
	}
	acceptAt := strings.Index(body, "DisconnectRequest.accept(")
	if acceptAt < 0 {
		t.Fatal("handleIntent kesme isteğini gönderen bileşeni denetlemiyor (DisconnectRequest.accept yok)")
	}
	if !strings.Contains(body[acceptAt:], "intent.component?.className") {
		t.Fatal("handleIntent, accept'e niyetin bileşen adını vermiyor")
	}
	call := strings.Index(body, "disconnect()")
	if call < 0 || call < acceptAt {
		t.Fatal("disconnect() accept denetiminden önce veya koşulsuz çağrılıyor")
	}
	if !regexp.MustCompile(`if \(accepted\) disconnect\(\)`).MatchString(body) {
		t.Fatal("disconnect() accept sonucuna bağlı değil")
	}
}

// Manifestteki ".DisconnectRequest" namespace'e göre çözülür; ALIAS_CLASS bunun
// tam adı değilse bildirim, kutucuk ve bileşen kesme isteği hiç çalışmaz.
func TestAndroidDisconnectAliasMatchesNamespace(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "android", "app", "build.gradle.kts"))
	if err != nil {
		t.Fatalf("build.gradle.kts okunamadı: %v", err)
	}
	m := regexp.MustCompile(`(?m)^\s*namespace\s*=\s*"([^"]+)"`).FindSubmatch(b)
	if m == nil {
		t.Fatal("namespace bulunamadı")
	}
	want := `const val ALIAS_CLASS = "` + string(m[1]) + `.DisconnectRequest"`
	if !strings.Contains(readAndroidFile(t, "kotlin/org/openscale/android/DisconnectRequest.kt"), want) {
		t.Fatalf("DisconnectRequest.kt içinde %s yok", want)
	}
}

// Kardeş yollar: MainActivity'nin başka bir yeri kesme eylemine bakmaz ve
// handleIntent'te koşulsuz ikinci bir kesme yoktur.
func TestAndroidDisconnectOnlyInHandleIntent(t *testing.T) {
	src := strings.ReplaceAll(readAndroidFile(t, "kotlin/org/openscale/android/MainActivity.kt"), "\r\n", "\n")
	start := strings.Index(src, "private fun handleIntent(")
	if start < 0 {
		t.Fatal("MainActivity.handleIntent bulunamadı")
	}
	end := strings.Index(src[start:], "\n    }\n")
	if end < 0 {
		t.Fatal("handleIntent sonu bulunamadı")
	}
	body := src[start : start+end]
	if n := strings.Count(body, "disconnect()"); n != 1 {
		t.Errorf("handleIntent içinde %d disconnect() var; yalnızca accept'e bağlı tek çağrı olmalı", n)
	}
	rest := src[:start] + src[start+end:]
	for _, name := range []string{"ACTION_REQUEST_DISCONNECT", "DisconnectRequest.ACTION"} {
		for _, line := range strings.Split(rest, "\n") {
			if strings.Contains(line, name) && !strings.Contains(line, "const val ACTION_REQUEST_DISCONNECT") {
				t.Errorf("handleIntent dışında kesme eylemi kullanılıyor: %s", strings.TrimSpace(line))
			}
		}
	}
}

// Değiştirilebilir bir PendingIntent, onu eline geçiren uygulamaya dışa kapalı
// takma adı kullandırabilirdi.
func TestAndroidPendingIntentsImmutable(t *testing.T) {
	dir := filepath.Join(androidSrc, "kotlin", "org", "openscale", "android")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("kotlin dizini okunamadı: %v", err)
	}
	call := regexp.MustCompile(`PendingIntent\.get(Activity|Service|ForegroundService|Broadcast)\(`)
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".kt") {
			continue
		}
		src := readAndroidFile(t, "kotlin/org/openscale/android/"+e.Name())
		if strings.Contains(src, "FLAG_MUTABLE") {
			t.Errorf("%s FLAG_MUTABLE kullanıyor", e.Name())
		}
		for _, loc := range call.FindAllStringIndex(src, -1) {
			found++
			end := min(loc[1]+300, len(src))
			window := src[loc[1]:end]
			if next := call.FindStringIndex(window); next != nil {
				window = window[:next[0]]
			}
			if !strings.Contains(window, "FLAG_IMMUTABLE") {
				t.Errorf("%s: PendingIntent FLAG_IMMUTABLE olmadan kuruluyor", e.Name())
			}
		}
	}
	if found == 0 {
		t.Fatal("hiç PendingIntent bulunamadı; desen eskimiş olabilir")
	}
}

func TestAndroidDisconnectAcceptRequiresAlias(t *testing.T) {
	src := readAndroidFile(t, "kotlin/org/openscale/android/DisconnectRequest.kt")
	for _, want := range []string{
		`const val ACTION = "org.openscale.android.REQUEST_DISCONNECT"`,
		`const val ALIAS_CLASS = "org.openscale.android.DisconnectRequest"`,
		"action == ACTION && componentClass == ALIAS_CLASS",
		"ComponentName(context, ALIAS_CLASS)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("DisconnectRequest.kt içinde beklenen yok: %s", want)
		}
	}
}
