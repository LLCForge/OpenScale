//go:build linux && cgo && !nopipewire

package rdesk

// The PipeWire bridge of the Wayland remote desktop (ADR-0236). The
// portal hands out a PipeWire connection (a file descriptor) and stream
// node ids; reading video from it needs libpipewire. The library is
// loaded with dlopen when a Wayland session starts, so the program still
// starts on systems without PipeWire and only needs the headers to build
// (Debian/Ubuntu libpipewire-0.3-dev, Fedora pipewire-devel, Arch
// libpipewire). Build with the nopipewire tag to leave the bridge out.
//
// Frames are copied out of the stream's buffers on PipeWire's own thread
// into one buffer per stream, under a mutex; Go copies the newest frame
// when the server asks. Only shared memory buffers (MemPtr, MemFd) in
// BGRx, RGBx, BGRA or RGBA are accepted; every size, stride and offset
// from the compositor is checked before memory is touched.

/*
#cgo CFLAGS: -I/usr/include/pipewire-0.3 -I/usr/include/spa-0.2 -D_REENTRANT
#cgo LDFLAGS: -ldl -lpthread
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pipewire/pipewire.h>
#include <spa/param/video/format-utils.h>
#include <spa/buffer/buffer.h>

#define OSP_MAX_STREAMS 8
#define OSP_MAX_DIM 8192

#define OSP_FUNCS(X) \
	X(pw_init) X(pw_thread_loop_new) X(pw_thread_loop_get_loop) X(pw_thread_loop_start) \
	X(pw_thread_loop_stop) X(pw_thread_loop_lock) X(pw_thread_loop_unlock) X(pw_thread_loop_destroy) \
	X(pw_context_new) X(pw_context_destroy) X(pw_context_connect_fd) X(pw_core_disconnect) \
	X(pw_properties_new) X(pw_stream_new) X(pw_stream_add_listener) X(pw_stream_connect) \
	X(pw_stream_disconnect) X(pw_stream_destroy) X(pw_stream_update_params) \
	X(pw_stream_dequeue_buffer) X(pw_stream_queue_buffer)

#define OSP_DECL(name) static __typeof__(name) *p_##name;
OSP_FUNCS(OSP_DECL)

static int osp_loaded = -1;
static pthread_mutex_t osp_load_mu = PTHREAD_MUTEX_INITIALIZER;

// osp_load opens libpipewire once; 1 when every function was found.
static int osp_load(void) {
	pthread_mutex_lock(&osp_load_mu);
	if (osp_loaded < 0) {
		osp_loaded = 0;
		void *h = dlopen("libpipewire-0.3.so.0", RTLD_NOW | RTLD_LOCAL);
		if (h != NULL) {
			int ok = 1;
#define OSP_LOAD(name) p_##name = (__typeof__(name) *)dlsym(h, #name); if (p_##name == NULL) ok = 0;
			OSP_FUNCS(OSP_LOAD)
			if (ok) {
				p_pw_init(NULL, NULL);
				osp_loaded = 1;
			} else {
				dlclose(h);
			}
		}
	}
	int r = osp_loaded;
	pthread_mutex_unlock(&osp_load_mu);
	return r;
}

typedef struct osp_ctx osp_ctx;

typedef struct {
	osp_ctx *ctx;
	struct pw_stream *stream;
	struct spa_hook listener;
	struct spa_video_info_raw format;
	int have_format;
	uint8_t *frame;
	size_t frame_cap;
	int w, h, bgr;
} osp_stream;

struct osp_ctx {
	struct pw_thread_loop *loop;
	struct pw_context *context;
	struct pw_core *core;
	pthread_mutex_t mu;
	int n;
	int failed;
	osp_stream streams[OSP_MAX_STREAMS];
};

static void osp_on_state_changed(void *data, enum pw_stream_state old, enum pw_stream_state state, const char *error) {
	osp_stream *s = data;
	if (state == PW_STREAM_STATE_ERROR || state == PW_STREAM_STATE_UNCONNECTED) {
		pthread_mutex_lock(&s->ctx->mu);
		if (state == PW_STREAM_STATE_ERROR) s->ctx->failed = 1;
		pthread_mutex_unlock(&s->ctx->mu);
	}
}

static void osp_on_param_changed(void *data, uint32_t id, const struct spa_pod *param) {
	osp_stream *s = data;
	if (param == NULL || id != SPA_PARAM_Format) return;
	uint32_t media_type = 0, media_subtype = 0;
	if (spa_format_parse(param, &media_type, &media_subtype) < 0) return;
	if (media_type != SPA_MEDIA_TYPE_video || media_subtype != SPA_MEDIA_SUBTYPE_raw) return;
	struct spa_video_info_raw info;
	memset(&info, 0, sizeof(info));
	if (spa_format_video_raw_parse(param, &info) < 0) return;
	pthread_mutex_lock(&s->ctx->mu);
	s->format = info;
	s->have_format = 1;
	pthread_mutex_unlock(&s->ctx->mu);
	// Shared memory only: the frame is read by the CPU.
	uint8_t buf[256];
	struct spa_pod_builder b = SPA_POD_BUILDER_INIT(buf, sizeof(buf));
	const struct spa_pod *params[1];
	params[0] = spa_pod_builder_add_object(&b,
		SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
		SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int((1 << SPA_DATA_MemPtr) | (1 << SPA_DATA_MemFd)));
	p_pw_stream_update_params(s->stream, params, 1);
}

static void osp_on_process(void *data) {
	osp_stream *s = data;
	struct pw_buffer *pb = p_pw_stream_dequeue_buffer(s->stream);
	if (pb == NULL) return;
	struct spa_buffer *buf = pb->buffer;
	if (buf != NULL && buf->n_datas > 0 && buf->datas[0].data != NULL && buf->datas[0].chunk != NULL) {
		struct spa_data *d = &buf->datas[0];
		pthread_mutex_lock(&s->ctx->mu);
		int have = s->have_format;
		uint32_t w = s->format.size.width, h = s->format.size.height, fmt = s->format.format;
		pthread_mutex_unlock(&s->ctx->mu);
		int bgr = fmt == SPA_VIDEO_FORMAT_BGRx || fmt == SPA_VIDEO_FORMAT_BGRA;
		int known = bgr || fmt == SPA_VIDEO_FORMAT_RGBx || fmt == SPA_VIDEO_FORMAT_RGBA;
		int64_t stride = d->chunk->stride;
		uint64_t off = d->chunk->offset, size = d->chunk->size;
		if (stride <= 0) stride = (int64_t)w * 4;
		if (have && known && (d->chunk->flags & SPA_CHUNK_FLAG_CORRUPTED) == 0 &&
		    w > 0 && h > 0 && w <= OSP_MAX_DIM && h <= OSP_MAX_DIM &&
		    (uint64_t)stride >= (uint64_t)w * 4 &&
		    off <= d->maxsize && size <= d->maxsize - off &&
		    (uint64_t)stride * (h - 1) + (uint64_t)w * 4 <= size) {
			size_t need = (size_t)w * h * 4;
			const uint8_t *src = (const uint8_t *)d->data + off;
			pthread_mutex_lock(&s->ctx->mu);
			if (s->frame_cap < need) {
				uint8_t *nf = realloc(s->frame, need);
				if (nf != NULL) {
					s->frame = nf;
					s->frame_cap = need;
				}
			}
			if (s->frame_cap >= need) {
				for (uint32_t y = 0; y < h; y++) {
					memcpy(s->frame + (size_t)y * w * 4, src + (size_t)y * (size_t)stride, (size_t)w * 4);
				}
				s->w = (int)w;
				s->h = (int)h;
				s->bgr = bgr;
			}
			pthread_mutex_unlock(&s->ctx->mu);
		}
	}
	p_pw_stream_queue_buffer(s->stream, pb);
}

static const struct pw_stream_events osp_stream_events = {
	PW_VERSION_STREAM_EVENTS,
	.state_changed = osp_on_state_changed,
	.param_changed = osp_on_param_changed,
	.process = osp_on_process,
};

static void osp_close(osp_ctx *c) {
	if (c == NULL) return;
	// With the loop thread stopped nothing runs the callbacks any more.
	if (c->loop != NULL) p_pw_thread_loop_stop(c->loop);
	for (int i = 0; i < c->n; i++) {
		osp_stream *s = &c->streams[i];
		if (s->stream != NULL) {
			p_pw_stream_disconnect(s->stream);
			p_pw_stream_destroy(s->stream);
		}
		free(s->frame);
	}
	if (c->core != NULL) p_pw_core_disconnect(c->core);
	if (c->context != NULL) p_pw_context_destroy(c->context);
	if (c->loop != NULL) p_pw_thread_loop_destroy(c->loop);
	pthread_mutex_destroy(&c->mu);
	free(c);
}

// osp_open connects to the portal's PipeWire remote through its own copy
// of src (close-on-exec) and to the given nodes. NULL with *err 1: no
// libpipewire; 2: the connection or a stream failed.
static osp_ctx *osp_open(int src, const uint32_t *nodes, int n, int *err) {
	*err = 2;
	int fd = fcntl(src, F_DUPFD_CLOEXEC, 3);
	if (fd < 0) return NULL;
	if (n <= 0 || n > OSP_MAX_STREAMS) {
		close(fd);
		return NULL;
	}
	if (osp_load() != 1) {
		close(fd);
		*err = 1;
		return NULL;
	}
	osp_ctx *c = calloc(1, sizeof(*c));
	if (c == NULL) {
		close(fd);
		return NULL;
	}
	pthread_mutex_init(&c->mu, NULL);
	c->loop = p_pw_thread_loop_new("openscale-rdesk", NULL);
	if (c->loop != NULL) c->context = p_pw_context_new(p_pw_thread_loop_get_loop(c->loop), NULL, 0);
	if (c->context == NULL || p_pw_thread_loop_start(c->loop) < 0) {
		close(fd);
		osp_close(c);
		return NULL;
	}
	p_pw_thread_loop_lock(c->loop);
	// The core owns fd from here, also when connecting fails.
	c->core = p_pw_context_connect_fd(c->context, fd, NULL, 0);
	int ok = c->core != NULL;
	for (int i = 0; ok && i < n; i++) {
		osp_stream *s = &c->streams[i];
		s->ctx = c;
		struct pw_properties *props = p_pw_properties_new(PW_KEY_MEDIA_TYPE, "Video",
			PW_KEY_MEDIA_CATEGORY, "Capture", PW_KEY_MEDIA_ROLE, "Screen", NULL);
		s->stream = p_pw_stream_new(c->core, "openscale-rdesk", props);
		if (s->stream == NULL) {
			ok = 0;
			break;
		}
		c->n = i + 1;
		p_pw_stream_add_listener(s->stream, &s->listener, &osp_stream_events, s);
		uint8_t buf[1024];
		struct spa_pod_builder b = SPA_POD_BUILDER_INIT(buf, sizeof(buf));
		struct spa_rectangle def = SPA_RECTANGLE(1920, 1080), mn = SPA_RECTANGLE(1, 1), mx = SPA_RECTANGLE(OSP_MAX_DIM, OSP_MAX_DIM);
		struct spa_fraction fdef = SPA_FRACTION(30, 1), fmn = SPA_FRACTION(0, 1), fmx = SPA_FRACTION(240, 1);
		const struct spa_pod *params[1];
		params[0] = spa_pod_builder_add_object(&b,
			SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat,
			SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
			SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
			SPA_FORMAT_VIDEO_format, SPA_POD_CHOICE_ENUM_Id(5, SPA_VIDEO_FORMAT_BGRx, SPA_VIDEO_FORMAT_BGRx,
				SPA_VIDEO_FORMAT_RGBx, SPA_VIDEO_FORMAT_BGRA, SPA_VIDEO_FORMAT_RGBA),
			SPA_FORMAT_VIDEO_size, SPA_POD_CHOICE_RANGE_Rectangle(&def, &mn, &mx),
			SPA_FORMAT_VIDEO_framerate, SPA_POD_CHOICE_RANGE_Fraction(&fdef, &fmn, &fmx));
		if (p_pw_stream_connect(s->stream, PW_DIRECTION_INPUT, nodes[i],
		                        PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS, params, 1) < 0) {
			ok = 0;
		}
	}
	p_pw_thread_loop_unlock(c->loop);
	if (!ok) {
		osp_close(c);
		return NULL;
	}
	*err = 0;
	return c;
}

// osp_frame copies stream i's newest frame (4 bytes per pixel, rows
// packed) into dst. 0: copied; 1: no frame yet; 2: dst is smaller than
// *w * *h * 4; 3: the stream failed.
static int osp_frame(osp_ctx *c, int i, uint8_t *dst, size_t cap, int *w, int *h, int *bgr) {
	if (i < 0 || i >= c->n) return 3;
	osp_stream *s = &c->streams[i];
	int r;
	pthread_mutex_lock(&c->mu);
	*w = s->w;
	*h = s->h;
	*bgr = s->bgr;
	if (c->failed) {
		r = 3;
	} else if (s->w == 0 || s->h == 0) {
		r = 1;
	} else if (dst == NULL || cap < (size_t)s->w * s->h * 4) {
		r = 2;
	} else {
		memcpy(dst, s->frame, (size_t)s->w * s->h * 4);
		r = 0;
	}
	pthread_mutex_unlock(&c->mu);
	return r;
}

static void osp_size(osp_ctx *c, int i, int *w, int *h) {
	*w = 0;
	*h = 0;
	if (i < 0 || i >= c->n) return;
	pthread_mutex_lock(&c->mu);
	*w = c->streams[i].w;
	*h = c->streams[i].h;
	pthread_mutex_unlock(&c->mu);
}
*/
import "C"

import (
	"fmt"
	"image"
	"os"
	"sync"
	"unsafe"
)

type pwBridge struct {
	mu  sync.Mutex
	c   *C.osp_ctx
	raw []byte
}

// openPipeWire connects to the portal's PipeWire remote; f stays the
// caller's (the bridge works on its own copy of the descriptor).
func openPipeWire(f *os.File, nodes []uint32) (pipewireFrames, error) {
	if len(nodes) == 0 || len(nodes) > maxPortalStreams {
		return nil, fmt.Errorf("%w: akış sayısı", ErrUnsupported)
	}
	cnodes := make([]C.uint32_t, len(nodes))
	for i, n := range nodes {
		cnodes[i] = C.uint32_t(n)
	}
	var cerr C.int
	// The C side duplicates the descriptor; f stays open until it returns.
	c := C.osp_open(C.int(f.Fd()), &cnodes[0], C.int(len(nodes)), &cerr)
	if c == nil {
		if cerr == 1 {
			return nil, fmt.Errorf("%w: libpipewire-0.3 yüklenemedi (PipeWire kurulu mu?)", ErrUnsupported)
		}
		return nil, fmt.Errorf("%w: PipeWire akışına bağlanılamadı", ErrUnsupported)
	}
	return &pwBridge{c: c}, nil
}

func (p *pwBridge) frame(i int, buf []byte) ([]byte, image.Point, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c == nil {
		return buf, image.Point{}, ErrScreenUnavailable
	}
	for attempt := 0; attempt < 2; attempt++ {
		var w, h, bgr C.int
		var ptr *C.uint8_t
		if len(p.raw) > 0 {
			ptr = (*C.uint8_t)(unsafe.Pointer(&p.raw[0]))
		}
		switch C.osp_frame(p.c, C.int(i), ptr, C.size_t(len(p.raw)), &w, &h, &bgr) {
		case 0:
			n := int(w) * int(h) * 4
			if cap(buf) < n {
				buf = make([]byte, n)
			}
			buf = buf[:n]
			if !frameToRGBA(buf, p.raw, int(w), int(h), int(w)*4, bgr != 0) {
				return buf, image.Point{}, ErrScreenUnavailable
			}
			return buf, image.Pt(int(w), int(h)), nil
		case 1:
			return buf, image.Point{}, nil
		case 2:
			p.raw = make([]byte, int(w)*int(h)*4)
		default:
			return buf, image.Point{}, ErrScreenUnavailable
		}
	}
	return buf, image.Point{}, nil
}

func (p *pwBridge) size(i int) image.Point {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c == nil {
		return image.Point{}
	}
	var w, h C.int
	C.osp_size(p.c, C.int(i), &w, &h)
	return image.Pt(int(w), int(h))
}

func (p *pwBridge) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c != nil {
		C.osp_close(p.c)
		p.c = nil
	}
}
