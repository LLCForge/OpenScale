//go:build linux && cgo && !nowebview

package webview

/*
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Implemented in Go (export_cgo.go).
extern int openscaleWebviewDecide(uintptr_t h, char *u, int user, int mainFrame);

typedef struct {
	uintptr_t handle;
	GtkWidget *window;
	WebKitWebView *view;
	guint generation;
} osw_state;

static osw_state *osw_current;
static guint osw_generation;
static int osw_gtk_ready = -1;

static void osw_open_external(osw_state *s, const char *uri) {
	if (uri == NULL || g_ascii_strncasecmp(uri, "https://", 8) != 0) return;
	gtk_show_uri_on_window(GTK_WINDOW(s->window), uri, GDK_CURRENT_TIME, NULL);
}

static gboolean osw_decide_policy(WebKitWebView *view, WebKitPolicyDecision *decision,
                                  WebKitPolicyDecisionType type, gpointer data) {
	osw_state *s = data;
	switch (type) {
	case WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION:
	case WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION: {
		WebKitNavigationPolicyDecision *nd = WEBKIT_NAVIGATION_POLICY_DECISION(decision);
		WebKitNavigationAction *action = webkit_navigation_policy_decision_get_navigation_action(nd);
		WebKitURIRequest *req = webkit_navigation_action_get_request(action);
		gchar *uri = g_strdup(webkit_uri_request_get_uri(req));
		int user = webkit_navigation_action_is_user_gesture(action) ? 1 : 0;
		int r = openscaleWebviewDecide(s->handle, uri, user, 1);
		if (type == WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION) {
			// Never a new window: the panel opens here.
			webkit_policy_decision_ignore(decision);
			if (r == 1) webkit_web_view_load_uri(view, uri);
			else if (r == 2) osw_open_external(s, uri);
		} else if (r == 1) {
			webkit_policy_decision_use(decision);
		} else {
			webkit_policy_decision_ignore(decision);
			if (r == 2) osw_open_external(s, uri);
		}
		g_free(uri);
		return TRUE;
	}
	case WEBKIT_POLICY_DECISION_TYPE_RESPONSE: {
		WebKitResponsePolicyDecision *rd = WEBKIT_RESPONSE_POLICY_DECISION(decision);
		// Whatever the engine cannot show would become a download.
		if (!webkit_response_policy_decision_is_mime_type_supported(rd)) {
			webkit_policy_decision_ignore(decision);
			return TRUE;
		}
		return FALSE;
	}
	default:
		return FALSE;
	}
}

static gboolean osw_permission(WebKitWebView *v, WebKitPermissionRequest *req, gpointer d) {
	webkit_permission_request_deny(req);
	return TRUE;
}

static gboolean osw_authenticate(WebKitWebView *v, WebKitAuthenticationRequest *req, gpointer d) {
	webkit_authentication_request_cancel(req);
	return TRUE;
}

static gboolean osw_context_menu(WebKitWebView *v, WebKitContextMenu *m, GdkEvent *e,
                                 WebKitHitTestResult *h, gpointer d) {
	return TRUE;
}

static GtkWidget *osw_create(WebKitWebView *v, WebKitNavigationAction *a, gpointer d) {
	return NULL;
}

static gboolean osw_tls_error(WebKitWebView *v, gchar *uri, GTlsCertificate *c,
                              GTlsCertificateFlags f, gpointer d) {
	// Handled: no exception is ever added, nothing is loaded.
	return TRUE;
}

static void osw_download(WebKitWebContext *ctx, WebKitDownload *dl, gpointer d) {
	webkit_download_cancel(dl);
}

static void osw_destroy(GtkWidget *w, gpointer data) {
	osw_state *s = data;
	if (osw_current == s) osw_current = NULL;
	gtk_main_quit();
}

static int osw_init(void) {
	if (osw_gtk_ready < 0) {
		osw_gtk_ready = gtk_init_check(NULL, NULL) ? 1 : 0;
	}
	return osw_gtk_ready;
}

// osw_run returns 0 after the window closed, 1 when GTK cannot start
// (no display).
static int osw_run(uintptr_t handle, const char *url, const char *title, int w, int h,
                   int minw, int minh, const unsigned char *icon, int iconLen,
                   const char *dataDir, const char *cacheDir,
                   const char *proxy, const char *bypass) {
	if (!osw_init()) return 1;

	WebKitWebsiteDataManager *mgr = webkit_website_data_manager_new(
	    "base-data-directory", dataDir, "base-cache-directory", cacheDir, NULL);
	WebKitWebContext *ctx = webkit_web_context_new_with_website_data_manager(mgr);
	webkit_web_context_set_cache_model(ctx, WEBKIT_CACHE_MODEL_DOCUMENT_VIEWER);

	// Network guard: every request outside the origin goes to the origin
	// itself as a proxy, which refuses the foreign Host.
	const gchar *ignore[] = {bypass, NULL};
	WebKitNetworkProxySettings *ps = webkit_network_proxy_settings_new(proxy, ignore);
#if WEBKIT_CHECK_VERSION(2, 32, 0)
	webkit_website_data_manager_set_network_proxy_settings(mgr, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, ps);
#else
	webkit_web_context_set_network_proxy_settings(ctx, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, ps);
#endif
	webkit_network_proxy_settings_free(ps);
	g_signal_connect(ctx, "download-started", G_CALLBACK(osw_download), NULL);

	WebKitWebView *view = WEBKIT_WEB_VIEW(webkit_web_view_new_with_context(ctx));
	WebKitSettings *st = webkit_web_view_get_settings(view);
	webkit_settings_set_enable_developer_extras(st, FALSE);
	webkit_settings_set_javascript_can_open_windows_automatically(st, FALSE);
	webkit_settings_set_javascript_can_access_clipboard(st, FALSE);
	webkit_settings_set_enable_write_console_messages_to_stdout(st, FALSE);
	webkit_settings_set_allow_file_access_from_file_urls(st, FALSE);
	webkit_settings_set_allow_universal_access_from_file_urls(st, FALSE);

	osw_state *s = g_new0(osw_state, 1);
	s->handle = handle;
	s->view = view;
	s->generation = ++osw_generation;

	GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	s->window = win;
	gtk_window_set_title(GTK_WINDOW(win), title);
	gtk_window_set_default_size(GTK_WINDOW(win), w, h);
	GdkGeometry geo = {0};
	geo.min_width = minw;
	geo.min_height = minh;
	gtk_window_set_geometry_hints(GTK_WINDOW(win), NULL, &geo, GDK_HINT_MIN_SIZE);
	gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER);
	if (icon != NULL && iconLen > 0) {
		GdkPixbufLoader *ld = gdk_pixbuf_loader_new_with_type("png", NULL);
		if (ld != NULL) {
			if (gdk_pixbuf_loader_write(ld, icon, (gsize)iconLen, NULL) && gdk_pixbuf_loader_close(ld, NULL)) {
				GdkPixbuf *pb = gdk_pixbuf_loader_get_pixbuf(ld);
				if (pb != NULL) gtk_window_set_icon(GTK_WINDOW(win), pb);
			}
			g_object_unref(ld);
		}
	}

	g_signal_connect(view, "decide-policy", G_CALLBACK(osw_decide_policy), s);
	g_signal_connect(view, "permission-request", G_CALLBACK(osw_permission), s);
	g_signal_connect(view, "authenticate", G_CALLBACK(osw_authenticate), s);
	g_signal_connect(view, "context-menu", G_CALLBACK(osw_context_menu), s);
	g_signal_connect(view, "create", G_CALLBACK(osw_create), s);
	g_signal_connect(view, "load-failed-with-tls-errors", G_CALLBACK(osw_tls_error), s);
	g_signal_connect(win, "destroy", G_CALLBACK(osw_destroy), s);

	gtk_container_add(GTK_CONTAINER(win), GTK_WIDGET(view));
	osw_current = s;
	webkit_web_view_load_uri(view, url);
	gtk_widget_show_all(win);
	gtk_window_present(GTK_WINDOW(win));
	gtk_main();

	osw_current = NULL;
	g_free(s);
	g_object_unref(ctx);
	g_object_unref(mgr);
	return 0;
}

static gboolean osw_close_idle(gpointer data) {
	guint gen = GPOINTER_TO_UINT(data);
	if (osw_current != NULL && osw_current->generation == gen) {
		gtk_widget_destroy(osw_current->window);
	}
	return G_SOURCE_REMOVE;
}

static guint osw_current_generation(void) { return osw_generation; }

// osw_close may be called from any thread.
static void osw_close(guint gen) { g_idle_add(osw_close_idle, GUINT_TO_POINTER(gen)); }

typedef struct {
	guint generation;
	gchar *uri;
} osw_forward_job;

static gboolean osw_forward_idle(gpointer data) {
	osw_forward_job *job = data;
	if (osw_current != NULL && osw_current->generation == job->generation) {
		webkit_web_view_load_uri(osw_current->view, job->uri);
		gtk_window_present(GTK_WINDOW(osw_current->window));
	}
	g_free(job->uri);
	g_free(job);
	return G_SOURCE_REMOVE;
}

// osw_forward loads uri in the window of generation gen and brings it to
// the front; it may be called from any thread. A window that closed in
// the meantime (another generation) ignores it.
static void osw_forward(guint gen, const char *uri) {
	osw_forward_job *job = g_new0(osw_forward_job, 1);
	job->generation = gen;
	job->uri = g_strdup(uri);
	g_idle_add(osw_forward_idle, job);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/cgo"
	"sync"
	"unsafe"
)

// GTK is used from one dedicated OS thread for the life of the process;
// windows are shown one after another on it.
var (
	gtkOnce sync.Once
	gtkJobs chan func()
)

func gtkThread() {
	runtime.LockOSThread()
	for job := range gtkJobs {
		job()
	}
}

func onGTKThread(job func()) {
	gtkOnce.Do(func() {
		gtkJobs = make(chan func())
		go gtkThread()
	})
	done := make(chan struct{})
	gtkJobs <- func() { defer close(done); job() }
	<-done
}

// linuxDataDirs returns the data and cache folders below XDG_DATA_HOME
// and XDG_CACHE_HOME (or their ~/.local defaults).
func linuxDataDirs(override string) (string, string, error) {
	if override != "" {
		return filepath.Join(override, "data"), filepath.Join(override, "cache"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	data := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(data) {
		data = filepath.Join(home, ".local", "share")
	}
	cache := os.Getenv("XDG_CACHE_HOME")
	if !filepath.IsAbs(cache) {
		cache = filepath.Join(home, ".cache")
	}
	return filepath.Join(data, "openscale", "webview"), filepath.Join(cache, "openscale", "webview"), nil
}

// privateDir creates dir with 0700 and refuses a link in its place.
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("klasör değil")
	}
	return os.Chmod(dir, 0o700)
}

func open(ctx context.Context, cfg config) error {
	dataDir, cacheDir, err := linuxDataDirs(cfg.dataDir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	for _, d := range []string{dataDir, cacheDir} {
		if err := privateDir(d); err != nil {
			return fmt.Errorf("%w: veri klasörü: %v", ErrUnavailable, err)
		}
	}
	h := cgo.NewHandle(&cfg)
	defer h.Delete()

	cs := func(s string) *C.char { return C.CString(s) }
	curl, ctitle := cs(cfg.url), cs(cfg.title)
	cdata, ccache := cs(dataDir), cs(cacheDir)
	hp := cfg.origin.String()
	cproxy := cs(hp)
	cbypass := cs(hp[len("http://"):])
	defer func() {
		for _, p := range []*C.char{curl, ctitle, cdata, ccache, cproxy, cbypass} {
			C.free(unsafe.Pointer(p))
		}
	}()
	var icon unsafe.Pointer
	if len(cfg.iconPNG) > 0 {
		icon = C.CBytes(cfg.iconPNG)
		defer C.free(icon)
	}

	var r C.int
	var gen C.guint
	started := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		select {
		case <-started:
		case <-stop:
			return
		}
		select {
		case <-ctx.Done():
			C.osw_close(gen)
		case <-stop:
		}
	}()
	onGTKThread(func() {
		if ctx.Err() != nil {
			r = -1
			return
		}
		// The next window gets this generation; osw_close compares it.
		gen = C.osw_current_generation() + 1
		openWindow.set(&cfg, gen)
		defer openWindow.set(nil, 0)
		close(started)
		r = C.osw_run(C.uintptr_t(h), curl, ctitle, C.int(cfg.width), C.int(cfg.height),
			C.int(cfg.minWidth), C.int(cfg.minHeight), (*C.uchar)(icon), C.int(len(cfg.iconPNG)),
			cdata, ccache, cproxy, cbypass)
	})
	close(stop)
	switch r {
	case 0, -1:
		return ctx.Err()
	case 1:
		return fmt.Errorf("%w: GTK başlatılamadı (grafik oturumu yok mu?)", ErrUnavailable)
	default:
		return fmt.Errorf("%w: WebKitGTK ağ koruması kurulamadı", ErrUnavailable)
	}
}

// openWindow is the window on the GTK thread, for forwarding.
var openWindow linuxOpenWindow

type linuxOpenWindow struct {
	mu  sync.Mutex
	cfg *config
	gen C.guint
}

func (w *linuxOpenWindow) set(cfg *config, gen C.guint) {
	w.mu.Lock()
	w.cfg, w.gen = cfg, gen
	w.mu.Unlock()
}

// ForwardToOpenWindow loads a fresh sign-in address in the open panel
// window of this program and brings it to the front (Linux: the window
// lives in this process, so the check is not used). The address must
// pass the window's forward rule.
func ForwardToOpenWindow(link string, _ TargetCheck) error {
	openWindow.mu.Lock()
	cfg, gen := openWindow.cfg, openWindow.gen
	openWindow.mu.Unlock()
	if cfg == nil {
		return ErrNoOpenWindow
	}
	if !cfg.acceptForward(link) {
		return errForwardRefused
	}
	cl := C.CString(link)
	defer C.free(unsafe.Pointer(cl))
	C.osw_forward(gen, cl)
	return nil
}
