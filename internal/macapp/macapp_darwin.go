//go:build darwin && cgo

package macapp

/*
#cgo CFLAGS: -x objective-c -fobjc-arc -mmacosx-version-min=12.0
#cgo LDFLAGS: -framework Cocoa -framework UserNotifications

// memset_s (C11 Annex K) is declared only when this is set first.
#define __STDC_WANT_LIB_EXT1__ 1
#import <Cocoa/Cocoa.h>
#import <UserNotifications/UserNotifications.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Implemented in Go (export_darwin.go); called on the main thread.
extern void openscaleMacappClicked(int id);
extern void openscaleMacappReopen(int unused);
extern void openscaleMacappReady(int unused);
extern void openscaleMacappReply(uint64_t req, int ok, char *text);

static void osm_main(dispatch_block_t b) {
	CFRunLoopPerformBlock(CFRunLoopGetMain(), kCFRunLoopCommonModes, b);
	CFRunLoopWakeUp(CFRunLoopGetMain());
}

static NSString *osm_str(const char *s) {
	if (s == NULL) return @"";
	NSString *v = [NSString stringWithUTF8String:s];
	return v != nil ? v : @"";
}

@interface OSMController : NSObject <NSApplicationDelegate>
@property(nonatomic, strong) NSStatusItem *item;
@end

@implementation OSMController
- (void)clicked:(NSMenuItem *)sender {
	openscaleMacappClicked((int)sender.tag);
}

// The user opened the app again (Finder, Spotlight, Dock) while it runs.
- (BOOL)applicationShouldHandleReopen:(NSApplication *)app hasVisibleWindows:(BOOL)visible {
	openscaleMacappReopen(0);
	return NO;
}
@end

static OSMController *osmCtl;

static int osm_is_main_thread(void) { return pthread_main_np() ? 1 : 0; }

// osm_title builds "label  detail" with the detail in the secondary
// colour; bold for the default item.
static NSAttributedString *osm_title(NSString *label, NSString *detail, BOOL bold, BOOL disabled) {
	NSFont *font = bold ? [NSFont boldSystemFontOfSize:[NSFont systemFontSize]] : [NSFont menuFontOfSize:0];
	NSColor *color = disabled ? [NSColor disabledControlTextColor] : [NSColor labelColor];
	NSMutableAttributedString *s = [[NSMutableAttributedString alloc]
	    initWithString:label
	        attributes:@{NSFontAttributeName : font, NSForegroundColorAttributeName : color}];
	if (detail.length > 0) {
		NSString *tail = [@"   " stringByAppendingString:detail];
		[s appendAttributedString:[[NSAttributedString alloc]
		                              initWithString:tail
		                                  attributes:@{
			                                  NSFontAttributeName : [NSFont menuFontOfSize:0],
			                                  NSForegroundColorAttributeName : [NSColor secondaryLabelColor]
		                                  }]];
	}
	return s;
}

static NSString *osm_field(NSDictionary *d, NSString *key) {
	id v = d[key];
	return [v isKindOfClass:[NSString class]] ? v : @"";
}

static BOOL osm_flag(NSDictionary *d, NSString *key) {
	id v = d[key];
	return [v isKindOfClass:[NSNumber class]] && [v boolValue];
}

// osm_menu builds an NSMenu from the JSON items Go sent (menu.go).
static NSMenu *osm_menu(NSArray *items, int depth) {
	NSMenu *m = [[NSMenu alloc] init];
	m.autoenablesItems = NO;
	if (depth > 4) return m;
	for (id obj in items) {
		if (![obj isKindOfClass:[NSDictionary class]]) continue;
		NSDictionary *d = obj;
		if (osm_flag(d, @"sep")) {
			[m addItem:[NSMenuItem separatorItem]];
			continue;
		}
		NSString *label = osm_field(d, @"label");
		NSString *detail = osm_field(d, @"detail");
		BOOL disabled = osm_flag(d, @"disabled");
		BOOL bold = osm_flag(d, @"bold");
		NSInteger ident = 0;
		if ([d[@"id"] isKindOfClass:[NSNumber class]]) ident = [d[@"id"] integerValue];
		NSMenuItem *it = [[NSMenuItem alloc] initWithTitle:label action:nil keyEquivalent:@""];
		if (detail.length > 0 || bold || disabled) {
			it.attributedTitle = osm_title(label, detail, bold, disabled);
		}
		id children = d[@"children"];
		if ([children isKindOfClass:[NSArray class]] && [children count] > 0) {
			NSMenu *sub = osm_menu(children, depth + 1);
			sub.title = label;
			it.submenu = sub;
		} else if (ident > 0 && ident <= 65535 && !disabled) {
			it.target = osmCtl;
			it.action = @selector(clicked:);
			it.tag = ident;
		}
		it.enabled = !disabled;
		if (osm_flag(d, @"checked")) it.state = NSControlStateValueOn;
		[m addItem:it];
	}
	return m;
}

static void osm_set_menu(const char *json, int len) {
	NSData *data = [NSData dataWithBytes:json length:(NSUInteger)len];
	osm_main(^{
		if (osmCtl == nil) return;
		id parsed = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
		if (![parsed isKindOfClass:[NSArray class]]) return;
		osmCtl.item.menu = osm_menu(parsed, 0);
	});
}

// osm_set_icon shows a template image (tinted by the system for light
// and dark menu bars); without an image the title text shows instead.
static void osm_set_icon(const void *png, int len, const char *fallback) {
	NSData *data = (png != NULL && len > 0) ? [NSData dataWithBytes:png length:(NSUInteger)len] : nil;
	NSString *title = osm_str(fallback);
	osm_main(^{
		if (osmCtl == nil) return;
		NSImage *img = data != nil ? [[NSImage alloc] initWithData:data] : nil;
		if (img != nil) {
			img.template = YES;
			img.size = NSMakeSize(18, 18);
			osmCtl.item.button.image = img;
			osmCtl.item.button.title = @"";
			osmCtl.item.button.imagePosition = NSImageOnly;
		} else {
			osmCtl.item.button.image = nil;
			osmCtl.item.button.title = title;
		}
		osmCtl.item.button.accessibilityLabel = title;
	});
}

static void osm_set_tooltip(const char *tip) {
	NSString *t = osm_str(tip);
	osm_main(^{
		if (osmCtl == nil) return;
		osmCtl.item.button.toolTip = t;
	});
}

// osm_notify posts a user notification; it needs the app bundle (a bare
// program has no bundle identifier and would crash the center).
static void osm_notify(const char *title, const char *body) {
	NSString *t = osm_str(title);
	NSString *b = osm_str(body);
	if ([[NSBundle mainBundle] bundleIdentifier] == nil) return;
	UNUserNotificationCenter *c = [UNUserNotificationCenter currentNotificationCenter];
	[c requestAuthorizationWithOptions:UNAuthorizationOptionAlert
	                 completionHandler:^(BOOL granted, NSError *err) {
		                 if (!granted) return;
		                 UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
		                 content.title = t;
		                 content.body = b;
		                 UNNotificationRequest *r = [UNNotificationRequest requestWithIdentifier:[[NSUUID UUID] UUIDString]
		                                                                                 content:content
		                                                                                 trigger:nil];
		                 [c addNotificationRequest:r withCompletionHandler:nil];
	                 }];
}

static void osm_copy(const char *text) {
	NSString *t = osm_str(text);
	osm_main(^{
		NSPasteboard *pb = [NSPasteboard generalPasteboard];
		[pb clearContents];
		[pb setString:t forType:NSPasteboardTypeString];
	});
}

// osm_alert shows a modal alert. kind 0: message only; 1: two buttons;
// 2: two buttons and a secure text field. The first paragraph is the
// title, the rest the explanation. cancelDefault makes Return choose the
// second button, as Windows does for questions with consequences. The
// answer goes to openscaleMacappReply unless req is 0.
static void osm_alert(uint64_t req, int kind, const char *msg, const char *okLabel,
                      const char *cancelLabel, int cancelDefault) {
	NSString *m = osm_str(msg);
	NSString *ok = osm_str(okLabel);
	NSString *cancel = osm_str(cancelLabel);
	osm_main(^{
		NSAlert *a = [[NSAlert alloc] init];
		NSRange split = [m rangeOfString:@"\n\n"];
		if (split.location != NSNotFound) {
			a.messageText = [m substringToIndex:split.location];
			a.informativeText = [m substringFromIndex:split.location + split.length];
		} else {
			a.messageText = m;
		}
		NSButton *first = [a addButtonWithTitle:(ok.length > 0 ? ok : @"Tamam")];
		NSSecureTextField *field = nil;
		if (kind >= 1) {
			NSButton *second = [a addButtonWithTitle:(cancel.length > 0 ? cancel : @"Vazgeç")];
			if (cancelDefault) {
				first.keyEquivalent = @"";
				second.keyEquivalent = @"\r";
			}
		}
		if (kind == 2) {
			field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 280, 24)];
			a.accessoryView = field;
			a.window.initialFirstResponder = field;
		}
		[NSApp activateIgnoringOtherApps:YES];
		NSModalResponse r = [a runModal];
		BOOL accepted = r == NSAlertFirstButtonReturn;
		if (req == 0) return;
		if (kind == 2 && accepted) {
			const char *typed = field.stringValue.UTF8String;
			size_t n = typed != NULL ? strlen(typed) : 0;
			char *buf = malloc(n + 1);
			if (buf == NULL) {
				openscaleMacappReply(req, 0, NULL);
				return;
			}
			memcpy(buf, typed != NULL ? typed : "", n + 1);
			field.stringValue = @"";
			openscaleMacappReply(req, 1, buf);
			memset_s(buf, n + 1, 0, n + 1);
			free(buf);
			return;
		}
		openscaleMacappReply(req, accepted ? 1 : 0, NULL);
	});
}

// osm_run owns the run loop until osm_stop; main thread only.
static void osm_run(const char *title) {
	@autoreleasepool {
		[NSApplication sharedApplication];
		// A menu bar app: no Dock icon until a window opens
		// (LSUIElement in Info.plist says the same for the bundle).
		[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
		osmCtl = [[OSMController alloc] init];
		NSApp.delegate = osmCtl;
		osmCtl.item = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
		osmCtl.item.button.title = osm_str(title);
		NSMenu *m = [[NSMenu alloc] init];
		NSMenuItem *wait = [[NSMenuItem alloc] initWithTitle:@"Servise bağlanılıyor..." action:nil keyEquivalent:@""];
		wait.enabled = NO;
		[m addItem:wait];
		osmCtl.item.menu = m;
		// Runs as the first thing inside the loop: from now on alerts
		// can be shown.
		osm_main(^{
			openscaleMacappReady(0);
		});
		[NSApp run];
		[[NSStatusBar systemStatusBar] removeStatusItem:osmCtl.item];
		NSApp.delegate = nil;
		osmCtl = nil;
	}
}

static void osm_stop(void) {
	osm_main(^{
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
	});
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

// AppKit runs only on the main thread: keep the main goroutine there.
func init() { runtime.LockOSThread() }

var (
	errNotMainThread = errors.New("macapp: Run programın ana goroutine'inden çağrılmalı")
	errRunning       = errors.New("macapp: menü çubuğu zaten çalışıyor")
	errMenuTooBig    = errors.New("macapp: menü çok büyük")
)

// maxMenuJSON bounds one menu update.
const maxMenuJSON = 256 << 10

// Item is one menu entry. Separator ignores the other fields; Children
// makes a submenu; ID 1..65535 makes the entry clickable.
type Item struct {
	ID        int    `json:"id,omitempty"`
	Label     string `json:"label,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
	Separator bool   `json:"sep,omitempty"`
	Checked   bool   `json:"checked,omitempty"`
	Bold      bool   `json:"bold,omitempty"`
	Children  []Item `json:"children,omitempty"`
}

// Config holds the callbacks; each runs on a new goroutine.
type Config struct {
	// Title is shown until an icon is set and read by VoiceOver.
	Title string
	// OnClick gets the id of a clicked item.
	OnClick func(id int)
	// OnReopen runs when the user opens the app again while it runs.
	OnReopen func()
	// OnReady runs once the run loop has started.
	OnReady func()
}

var (
	running  atomic.Bool
	handlers atomic.Pointer[Config]
)

// Run shows the status item and runs the AppKit loop until Quit or ctx
// ends. It must be called from the main goroutine.
func Run(ctx context.Context, cfg Config) error {
	if C.osm_is_main_thread() == 0 {
		return errNotMainThread
	}
	if !running.CompareAndSwap(false, true) {
		return errRunning
	}
	defer running.Store(false)
	handlers.Store(&cfg)
	defer handlers.Store(nil)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			C.osm_stop()
		case <-stop:
		}
	}()
	title := C.CString(cfg.Title)
	defer C.free(unsafe.Pointer(title))
	C.osm_run(title)
	return ctx.Err()
}

// Quit ends Run.
func Quit() { C.osm_stop() }

// SetMenu replaces the menu.
func SetMenu(items []Item) error {
	data, err := json.Marshal(items)
	if err != nil {
		return err
	}
	if len(data) > maxMenuJSON {
		return errMenuTooBig
	}
	p := C.CBytes(data)
	defer C.free(p)
	C.osm_set_menu((*C.char)(p), C.int(len(data)))
	return nil
}

// SetIcon shows png as a template image; nil shows fallback as text.
func SetIcon(png []byte, fallback string) {
	cf := C.CString(fallback)
	defer C.free(unsafe.Pointer(cf))
	if len(png) == 0 {
		C.osm_set_icon(nil, 0, cf)
		return
	}
	p := C.CBytes(png)
	defer C.free(p)
	C.osm_set_icon(p, C.int(len(png)), cf)
}

// SetTooltip sets the status item's help text.
func SetTooltip(tip string) {
	ct := C.CString(tip)
	defer C.free(unsafe.Pointer(ct))
	C.osm_set_tooltip(ct)
}

// Notify posts a notification (only from the app bundle).
func Notify(title, body string) {
	ct, cb := C.CString(title), C.CString(body)
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(cb))
	C.osm_notify(ct, cb)
}

// CopyText puts text on the clipboard.
func CopyText(text string) {
	c := C.CString(text)
	defer C.free(unsafe.Pointer(c))
	C.osm_copy(c)
}

// Message shows an alert with one button and does not wait.
func Message(msg string) { alert(0, 0, msg, "Tamam", "", false) }

// reply is a dialog answer.
type reply struct {
	ok   bool
	text []byte
}

var (
	reqMu   sync.Mutex
	reqNext uint64
	reqs    = map[uint64]chan reply{}
)

func newRequest() (uint64, chan reply) {
	reqMu.Lock()
	defer reqMu.Unlock()
	reqNext++
	ch := make(chan reply, 1)
	reqs[reqNext] = ch
	return reqNext, ch
}

// deliver hands an answer to its waiting caller.
func deliver(id uint64, r reply) {
	reqMu.Lock()
	ch, ok := reqs[id]
	delete(reqs, id)
	reqMu.Unlock()
	if ok {
		ch <- r
	}
}

func alert(id uint64, kind int, msg, ok, cancel string, cancelDefault bool) {
	cm, co, cc := C.CString(msg), C.CString(ok), C.CString(cancel)
	defer C.free(unsafe.Pointer(cm))
	defer C.free(unsafe.Pointer(co))
	defer C.free(unsafe.Pointer(cc))
	d := C.int(0)
	if cancelDefault {
		d = 1
	}
	C.osm_alert(C.uint64_t(id), C.int(kind), cm, co, cc, d)
}

// Confirm asks a yes/no question and waits for the answer. With
// cancelDefault, Return chooses cancel. It returns false on the main
// thread, where waiting would block the run loop that shows the alert.
func Confirm(msg, okLabel, cancelLabel string, cancelDefault bool) bool {
	if C.osm_is_main_thread() != 0 || !running.Load() {
		return false
	}
	id, ch := newRequest()
	alert(id, 1, msg, okLabel, cancelLabel, cancelDefault)
	return (<-ch).ok
}

// AskSecret asks for a passphrase in a secure text field (macOS turns on
// secure keyboard entry while it has focus). The caller wipes the result.
// ok is false when the user cancelled.
func AskSecret(msg, okLabel string) (secret []byte, ok bool) {
	if C.osm_is_main_thread() != 0 || !running.Load() {
		return nil, false
	}
	id, ch := newRequest()
	alert(id, 2, msg, okLabel, "Vazgeç", false)
	r := <-ch
	return r.text, r.ok
}
