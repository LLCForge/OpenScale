//go:build darwin && cgo && !nowebview

package webview

/*
#cgo CFLAGS: -x objective-c -fobjc-arc -mmacosx-version-min=12.0
#cgo LDFLAGS: -framework Cocoa -framework WebKit

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

// Implemented in Go (export_cgo.go, export_darwin.go).
extern int openscaleWebviewDecide(uintptr_t h, char *u, int user, int mainFrame);
extern int openscaleWebviewTheme(uintptr_t h, char *msg, char *pageURL, int *dark, int *r, int *g, int *b);
extern void openscaleWebviewClosed(uintptr_t h, int failed);

// Memory: this file is compiled with ARC (-fobjc-arc); objects are freed
// when the last strong reference goes. C strings from Go are copied into
// NSString/NSData before a function returns, because Go frees them right
// after the call. Threads: every AppKit and WebKit call runs on the main
// thread; functions called from other threads (osw_open_hosted,
// osw_close, osw_forward) only queue a block on the main run loop.

// A fixed identifier keeps one persistent, OpenScale-only website data
// store on macOS 14 and later.
static NSString *const oswStoreID = @"5B0E3C1A-7F4D-4C2B-9E61-0A9D3F2C8B47";

// The only message the page may post: "theme:<light|dark>:#rrggbb".
static NSString *const oswMessageName = @"openscale";
static const NSUInteger oswMaxMessage = 64;

// osw_main queues b on the main run loop in the common modes, so it also
// runs while a menu is open or a modal alert of the menu bar app shows.
static void osw_main(dispatch_block_t b) {
	CFRunLoopPerformBlock(CFRunLoopGetMain(), kCFRunLoopCommonModes, b);
	CFRunLoopWakeUp(CFRunLoopGetMain());
}

static int osw_decide(uintptr_t h, NSURL *url, BOOL user, BOOL mainFrame) {
	if (url == nil) return 0;
	const char *s = url.absoluteString.UTF8String;
	if (s == NULL) return 0;
	return openscaleWebviewDecide(h, (char *)s, user ? 1 : 0, mainFrame ? 1 : 0);
}

static void osw_open_external(NSURL *url) {
	if (url != nil && [url.scheme.lowercaseString isEqualToString:@"https"]) {
		[[NSWorkspace sharedWorkspace] openURL:url];
	}
}

// The context menu is emptied before it opens.
@interface OSWWebView : WKWebView
@end

@implementation OSWWebView
- (void)willOpenMenu:(NSMenu *)menu withEvent:(NSEvent *)event {
	[menu removeAllItems];
}
@end

@class OSWDelegate;

// The script message handler holds the delegate weakly: the content
// controller keeps its handlers alive, and a strong reference back would
// keep the window alive after it closed.
@interface OSWMessageHandler : NSObject <WKScriptMessageHandler>
@property(nonatomic, weak) OSWDelegate *owner;
@end

@interface OSWDelegate : NSObject <WKNavigationDelegate, WKUIDelegate, NSWindowDelegate>
@property(nonatomic) uintptr_t handle;
@property(nonatomic) BOOL hosted;
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) OSWWebView *webView;
- (void)applyThemeDark:(BOOL)dark red:(int)r green:(int)g blue:(int)b;
- (void)detach;
@end

static OSWDelegate *oswCurrent;

@implementation OSWMessageHandler
- (void)userContentController:(WKUserContentController *)controller
      didReceiveScriptMessage:(WKScriptMessage *)message {
	OSWDelegate *d = self.owner;
	if (d == nil || !message.frameInfo.isMainFrame) return;
	if (![message.body isKindOfClass:[NSString class]]) return;
	NSString *body = message.body;
	if (body.length == 0 || body.length > oswMaxMessage) return;
	NSString *page = d.webView.URL.absoluteString;
	const char *m = body.UTF8String;
	const char *p = page.UTF8String;
	if (m == NULL || p == NULL) return;
	int dark = 0, r = 0, g = 0, b = 0;
	if (openscaleWebviewTheme(d.handle, (char *)m, (char *)p, &dark, &r, &g, &b) == 1) {
		[d applyThemeDark:dark != 0 red:r green:g blue:b];
	}
}
@end

@implementation OSWDelegate

- (void)webView:(WKWebView *)webView
    decidePolicyForNavigationAction:(WKNavigationAction *)action
                    decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
	if (@available(macOS 11.3, *)) {
		if (action.shouldPerformDownload) {
			decisionHandler(WKNavigationActionPolicyCancel);
			return;
		}
	}
	NSURL *url = action.request.URL;
	BOOL user = action.navigationType == WKNavigationTypeLinkActivated;
	if (action.targetFrame == nil) {
		// A new-window request: never a new window. The panel itself
		// opens here, an https link the user clicked in the browser.
		decisionHandler(WKNavigationActionPolicyCancel);
		int r = osw_decide(self.handle, url, user, YES);
		if (r == 1) {
			[webView loadRequest:[NSURLRequest requestWithURL:url]];
		} else if (r == 2) {
			osw_open_external(url);
		}
		return;
	}
	BOOL mainFrame = action.targetFrame.isMainFrame;
	int r = osw_decide(self.handle, url, user, mainFrame);
	if (r == 1) {
		decisionHandler(WKNavigationActionPolicyAllow);
		return;
	}
	decisionHandler(WKNavigationActionPolicyCancel);
	if (r == 2 && mainFrame) {
		osw_open_external(url);
	}
}

- (void)webView:(WKWebView *)webView
    decidePolicyForNavigationResponse:(WKNavigationResponse *)response
                      decisionHandler:(void (^)(WKNavigationResponsePolicy))decisionHandler {
	// Whatever the engine cannot show would become a download.
	if (!response.canShowMIMEType) {
		decisionHandler(WKNavigationResponsePolicyCancel);
		return;
	}
	if ([response.response isKindOfClass:[NSHTTPURLResponse class]]) {
		NSString *cd = [(NSHTTPURLResponse *)response.response valueForHTTPHeaderField:@"Content-Disposition"];
		if (cd != nil && [cd.lowercaseString hasPrefix:@"attachment"]) {
			decisionHandler(WKNavigationResponsePolicyCancel);
			return;
		}
	}
	decisionHandler(WKNavigationResponsePolicyAllow);
}

// HTTP authentication prompts and every certificate question are refused.
- (void)webView:(WKWebView *)webView
    didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
	completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

- (WKWebView *)webView:(WKWebView *)webView
    createWebViewWithConfiguration:(WKWebViewConfiguration *)configuration
               forNavigationAction:(WKNavigationAction *)action
                    windowFeatures:(WKWindowFeatures *)features {
	return nil;
}

- (void)webView:(WKWebView *)webView
    requestMediaCapturePermissionForOrigin:(WKSecurityOrigin *)origin
                          initiatedByFrame:(WKFrameInfo *)frame
                                      type:(WKMediaCaptureType)type
                           decisionHandler:(void (^)(WKPermissionDecision))decisionHandler API_AVAILABLE(macos(12.0)) {
	decisionHandler(WKPermissionDecisionDeny);
}

- (void)webView:(WKWebView *)webView
    runJavaScriptAlertPanelWithMessage:(NSString *)message
                      initiatedByFrame:(WKFrameInfo *)frame
                     completionHandler:(void (^)(void))completionHandler {
	NSAlert *a = [[NSAlert alloc] init];
	a.messageText = message;
	[a beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
		completionHandler();
	}];
}

- (void)webView:(WKWebView *)webView
    runJavaScriptConfirmPanelWithMessage:(NSString *)message
                        initiatedByFrame:(WKFrameInfo *)frame
                       completionHandler:(void (^)(BOOL))completionHandler {
	NSAlert *a = [[NSAlert alloc] init];
	a.messageText = message;
	[a addButtonWithTitle:@"Tamam"];
	[a addButtonWithTitle:@"Vazgeç"];
	[a beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
		completionHandler(r == NSAlertFirstButtonReturn);
	}];
}

- (void)webView:(WKWebView *)webView
    runOpenPanelWithParameters:(WKOpenPanelParameters *)parameters
              initiatedByFrame:(WKFrameInfo *)frame
             completionHandler:(void (^)(NSArray<NSURL *> *))completionHandler {
	// Choosing a file is always the user's own action.
	NSOpenPanel *p = [NSOpenPanel openPanel];
	p.canChooseFiles = YES;
	p.canChooseDirectories = NO;
	p.allowsMultipleSelection = parameters.allowsMultipleSelection;
	[p beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
		completionHandler(r == NSModalResponseOK ? p.URLs : nil);
	}];
}

// The title bar takes the panel's background colour and light or dark
// appearance (the macOS side of the Windows "theme:" message).
- (void)applyThemeDark:(BOOL)dark red:(int)r green:(int)g blue:(int)b {
	NSWindow *w = self.window;
	if (w == nil) return;
	w.appearance = [NSAppearance appearanceNamed:(dark ? NSAppearanceNameDarkAqua : NSAppearanceNameAqua)];
	w.titlebarAppearsTransparent = YES;
	w.backgroundColor = [NSColor colorWithSRGBRed:r / 255.0 green:g / 255.0 blue:b / 255.0 alpha:1.0];
}

// detach cuts every link from the engine back to this object and Go, so
// no callback can arrive with a handle Go is about to delete.
- (void)detach {
	[self.webView stopLoading];
	[self.webView.configuration.userContentController removeScriptMessageHandlerForName:oswMessageName];
	self.webView.navigationDelegate = nil;
	self.webView.UIDelegate = nil;
	self.window.delegate = nil;
}

- (void)windowWillClose:(NSNotification *)notification {
	if (self.hosted) {
		// Hosted by the menu bar app: the program keeps running; only
		// this window goes. The last strong reference is dropped on a
		// later turn of the run loop, after AppKit finished closing.
		OSWDelegate *keep = self;
		[self detach];
		if (oswCurrent == self) oswCurrent = nil;
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
		openscaleWebviewClosed(self.handle, 0);
		osw_main(^{
			(void)keep;
		});
		return;
	}
	[NSApp stop:nil];
	// stop: takes effect after the next event; post one.
	NSEvent *e = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
	                                location:NSZeroPoint
	                           modifierFlags:0
	                               timestamp:0
	                            windowNumber:0
	                                 context:nil
	                                 subtype:0
	                                   data1:0
	                                   data2:0];
	[NSApp postEvent:e atStart:YES];
}
@end

static void osw_install_menu(void) {
	static BOOL done = NO;
	if (done) return;
	done = YES;
	NSMenu *bar = [[NSMenu alloc] init];
	NSMenuItem *appItem = [[NSMenuItem alloc] init];
	[bar addItem:appItem];
	NSMenu *appMenu = [[NSMenu alloc] init];
	[appMenu addItemWithTitle:@"Gizle" action:@selector(hide:) keyEquivalent:@"h"];
	[appMenu addItem:[NSMenuItem separatorItem]];
	[appMenu addItemWithTitle:@"Kapat" action:@selector(performClose:) keyEquivalent:@"w"];
	// Cmd+Q closes the window only; the program (menu bar, service) keeps running.
	[appMenu addItemWithTitle:@"Çık" action:@selector(performClose:) keyEquivalent:@"q"];
	appItem.submenu = appMenu;
	// The Edit menu makes copy and paste shortcuts work in the page.
	NSMenuItem *editItem = [[NSMenuItem alloc] init];
	[bar addItem:editItem];
	NSMenu *edit = [[NSMenu alloc] initWithTitle:@"Düzen"];
	[edit addItemWithTitle:@"Geri al" action:@selector(undo:) keyEquivalent:@"z"];
	[edit addItemWithTitle:@"Yinele" action:@selector(redo:) keyEquivalent:@"Z"];
	[edit addItem:[NSMenuItem separatorItem]];
	[edit addItemWithTitle:@"Kes" action:@selector(cut:) keyEquivalent:@"x"];
	[edit addItemWithTitle:@"Kopyala" action:@selector(copy:) keyEquivalent:@"c"];
	[edit addItemWithTitle:@"Yapıştır" action:@selector(paste:) keyEquivalent:@"v"];
	[edit addItemWithTitle:@"Tümünü seç" action:@selector(selectAll:) keyEquivalent:@"a"];
	editItem.submenu = edit;
	[NSApp setMainMenu:bar];
}

static int osw_is_main_thread(void) { return pthread_main_np() ? 1 : 0; }

// osw_build creates and shows the window on the main thread. It returns
// 0 on success, 1 when the address is not a URL.
static int osw_build(uintptr_t handle, NSString *url, NSString *title, int w, int h,
                     int minw, int minh, NSData *icon, BOOL hosted) {
	if (icon != nil) {
		NSImage *img = [[NSImage alloc] initWithData:icon];
		if (img != nil) [NSApp setApplicationIconImage:img];
	}
	NSURL *u = [NSURL URLWithString:url];
	if (u == nil) return 1;

	WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
	if (@available(macOS 14.0, *)) {
		cfg.websiteDataStore = [WKWebsiteDataStore dataStoreForIdentifier:[[NSUUID alloc] initWithUUIDString:oswStoreID]];
	} else {
		cfg.websiteDataStore = [WKWebsiteDataStore defaultDataStore];
	}
	cfg.preferences.javaScriptCanOpenWindowsAutomatically = NO;
	// The fraudulent-website check asks an outside service.
	cfg.preferences.fraudulentWebsiteWarningEnabled = NO;

	NSRect frame = NSMakeRect(0, 0, w, h);
	NSWindow *win = [[NSWindow alloc]
	    initWithContentRect:frame
	              styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
	                        NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
	                backing:NSBackingStoreBuffered
	                  defer:NO];
	win.releasedWhenClosed = NO;
	win.title = title;
	win.contentMinSize = NSMakeSize(minw, minh);
	// The window keeps its size and place between openings.
	[win setFrameAutosaveName:@"OpenScalePanel"];
	if (![win setFrameUsingName:@"OpenScalePanel"]) {
		[win center];
	}

	OSWWebView *wv = [[OSWWebView alloc] initWithFrame:frame configuration:cfg];
	if (@available(macOS 13.3, *)) {
		wv.inspectable = NO;
	}
	wv.allowsBackForwardNavigationGestures = NO;
	wv.allowsLinkPreview = NO;

	OSWDelegate *d = [[OSWDelegate alloc] init];
	d.handle = handle;
	d.hosted = hosted;
	d.window = win;
	d.webView = wv;
	OSWMessageHandler *mh = [[OSWMessageHandler alloc] init];
	mh.owner = d;
	[cfg.userContentController addScriptMessageHandler:mh name:oswMessageName];
	wv.navigationDelegate = d;
	wv.UIDelegate = d;
	win.delegate = d;
	win.contentView = wv;
	oswCurrent = d;

	[wv loadRequest:[NSURLRequest requestWithURL:u]];
	[win makeKeyAndOrderFront:nil];
	[NSApp activateIgnoringOtherApps:YES];
	return 0;
}

static NSData *osw_icon(const void *icon, int iconLen) {
	if (icon == NULL || iconLen <= 0) return nil;
	return [NSData dataWithBytes:icon length:(NSUInteger)iconLen];
}

// osw_run is the stand-alone window ("openscale window"): this function
// owns the run loop and returns when the window closes.
static int osw_run(uintptr_t handle, const char *url, const char *title, int w, int h,
                   int minw, int minh, const void *icon, int iconLen) {
	@autoreleasepool {
		[NSApplication sharedApplication];
		[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
		osw_install_menu();
		if (osw_build(handle, [NSString stringWithUTF8String:url], [NSString stringWithUTF8String:title],
		              w, h, minw, minh, osw_icon(icon, iconLen), NO) != 0) {
			return 1;
		}
		[NSApp run];
		OSWDelegate *d = oswCurrent;
		oswCurrent = nil;
		[d detach];
	}
	return 0;
}

// osw_open_hosted shows the window inside a run loop someone else runs
// (the menu bar app, internal/macapp). Any thread may call it; the result
// arrives through openscaleWebviewClosed.
static void osw_open_hosted(uintptr_t handle, const char *url, const char *title, int w, int h,
                            int minw, int minh, const void *icon, int iconLen) {
	NSString *u = [NSString stringWithUTF8String:url];
	NSString *t = [NSString stringWithUTF8String:title];
	NSData *img = osw_icon(icon, iconLen);
	osw_main(^{
		if (u == nil || t == nil || oswCurrent != nil) {
			openscaleWebviewClosed(handle, 1);
			return;
		}
		[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
		osw_install_menu();
		if (osw_build(handle, u, t, w, h, minw, minh, img, YES) != 0) {
			[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
			openscaleWebviewClosed(handle, 1);
		}
	});
}

// osw_close may be called from any thread.
static void osw_close(uintptr_t handle) {
	osw_main(^{
		if (oswCurrent != nil && oswCurrent.handle == handle) {
			[oswCurrent.window close];
		}
	});
}

// osw_forward loads a checked address in the open window and brings it to
// the front; any thread may call it.
static void osw_forward(uintptr_t handle, const char *url) {
	NSString *s = [NSString stringWithUTF8String:url];
	osw_main(^{
		if (s == nil || oswCurrent == nil || oswCurrent.handle != handle) return;
		NSURL *u = [NSURL URLWithString:s];
		if (u == nil) return;
		[oswCurrent.webView loadRequest:[NSURLRequest requestWithURL:u]];
		[oswCurrent.window deminiaturize:nil];
		[oswCurrent.window makeKeyAndOrderFront:nil];
		[NSApp activateIgnoringOtherApps:YES];
	});
}
*/
import "C"

import (
	"context"
	"errors"
	"runtime"
	"runtime/cgo"
	"sync"
	"time"
	"unsafe"
)

// AppKit runs only on the main thread: keep the main goroutine there.
func init() { runtime.LockOSThread() }

var (
	errNotMainThread = errors.New("webview: macOS'ta Open programın ana goroutine'inden çağrılmalı")
	errWindowOpen    = errors.New("webview: panel penceresi zaten açık")
	errBadStartURL   = errors.New("webview: başlangıç adresi açılamadı")
)

// hostedCloseWait bounds the wait for a window asked to close when the
// context ended (the run loop may already be gone at program exit).
const hostedCloseWait = 5 * time.Second

// hosted is the window shown inside the menu bar app's run loop; there is
// at most one.
var hosted struct {
	mu     sync.Mutex
	cfg    *config
	handle cgo.Handle
	done   chan bool // receives "failed" once, when the window is gone
}

func open(ctx context.Context, cfg config) error {
	if hostedRunLoop.Load() {
		return openHosted(ctx, cfg)
	}
	if C.osw_is_main_thread() == 0 {
		return errNotMainThread
	}
	h := cgo.NewHandle(&cfg)
	defer h.Delete()

	curl := C.CString(cfg.url)
	defer C.free(unsafe.Pointer(curl))
	ctitle := C.CString(cfg.title)
	defer C.free(unsafe.Pointer(ctitle))
	var icon unsafe.Pointer
	if len(cfg.iconPNG) > 0 {
		icon = C.CBytes(cfg.iconPNG)
		defer C.free(icon)
	}

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			C.osw_close(C.uintptr_t(h))
		case <-stop:
		}
	}()
	r := C.osw_run(C.uintptr_t(h), curl, ctitle, C.int(cfg.width), C.int(cfg.height),
		C.int(cfg.minWidth), C.int(cfg.minHeight), icon, C.int(len(cfg.iconPNG)))
	close(stop)
	if r != 0 {
		return errBadStartURL
	}
	return ctx.Err()
}

// openHosted shows the window in the run loop of the menu bar app. Any
// goroutine may call it; it blocks until the window is closed.
func openHosted(ctx context.Context, cfg config) error {
	c := cfg
	hosted.mu.Lock()
	if hosted.cfg != nil {
		hosted.mu.Unlock()
		return errWindowOpen
	}
	h := cgo.NewHandle(&c)
	done := make(chan bool, 1)
	hosted.cfg, hosted.handle, hosted.done = &c, h, done
	hosted.mu.Unlock()
	// The handle is deleted only once the window reported that it is
	// gone; a window that never did (the run loop ended first, at program
	// exit) keeps its handle, so a late callback cannot find it deleted.
	gone := false
	defer func() {
		hosted.mu.Lock()
		hosted.cfg, hosted.handle, hosted.done = nil, 0, nil
		hosted.mu.Unlock()
		if gone {
			h.Delete()
		}
	}()

	curl := C.CString(c.url)
	ctitle := C.CString(c.title)
	var icon unsafe.Pointer
	if len(c.iconPNG) > 0 {
		icon = C.CBytes(c.iconPNG)
	}
	// The native side copies everything before it returns.
	C.osw_open_hosted(C.uintptr_t(h), curl, ctitle, C.int(c.width), C.int(c.height),
		C.int(c.minWidth), C.int(c.minHeight), icon, C.int(len(c.iconPNG)))
	C.free(unsafe.Pointer(curl))
	C.free(unsafe.Pointer(ctitle))
	if icon != nil {
		C.free(icon)
	}

	select {
	case failed := <-done:
		gone = true
		if failed {
			return errBadStartURL
		}
		return nil
	case <-ctx.Done():
		C.osw_close(C.uintptr_t(h))
		select {
		case <-done:
			gone = true
		case <-time.After(hostedCloseWait):
		}
		return ctx.Err()
	}
}

// hostedClosed is called on the main thread when the hosted window is
// gone (or could not be created).
func hostedClosed(h uintptr, failed bool) {
	hosted.mu.Lock()
	defer hosted.mu.Unlock()
	if hosted.done == nil || uintptr(hosted.handle) != h {
		return
	}
	select {
	case hosted.done <- failed:
	default:
	}
}

// ForwardToOpenWindow loads a fresh sign-in address in the open panel
// window of this program and brings it to the front (macOS: the window
// lives in this process, so there is no other program to verify and the
// check is not used). The address must pass the window's forward rule.
func ForwardToOpenWindow(link string, _ TargetCheck) error {
	hosted.mu.Lock()
	c, h := hosted.cfg, hosted.handle
	hosted.mu.Unlock()
	if c == nil {
		return ErrNoOpenWindow
	}
	if !c.acceptForward(link) {
		return errForwardRefused
	}
	cl := C.CString(link)
	defer C.free(unsafe.Pointer(cl))
	C.osw_forward(C.uintptr_t(h), cl)
	return nil
}
