package healthmon

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Link quality history (#764): latency and loss per device in two ring
// buffers, five-minute buckets for the last day and one-hour buckets for
// the last seven days. Raw samples are folded into the buckets as they
// arrive (downsampling), so memory stays fixed per device.
const (
	FineStep     = 5 * time.Minute
	FineBuckets  = int(24 * time.Hour / FineStep)
	CoarseStep   = time.Hour
	CoarseBucket = int(7 * 24 * time.Hour / CoarseStep)
	MaxDevices   = 512
	maxDecode    = 32 << 20
)

// Resolution selects a ring.
type Resolution string

// Resolutions.
const (
	Fine   Resolution = "5m"
	Coarse Resolution = "1h"
)

type bucket struct {
	Start   int64  `json:"s"` // Unix seconds of the bucket start; 0 empty
	Samples uint32 `json:"n"`
	Lost    uint32 `json:"l"`
	SumUS   uint64 `json:"t"` // sum of answered RTTs in microseconds
	MaxUS   uint32 `json:"m"`
	MinUS   uint32 `json:"i"`
}

type ring struct {
	step    int64
	buckets []bucket
}

func newRing(step time.Duration, n int) ring {
	return ring{step: int64(step / time.Second), buckets: make([]bucket, n)}
}

func (r *ring) add(at time.Time, rtt time.Duration, lost bool) {
	start := at.Unix() - at.Unix()%r.step
	i := int((start / r.step) % int64(len(r.buckets)))
	b := &r.buckets[i]
	if b.Start != start {
		*b = bucket{Start: start}
	}
	b.Samples++
	if lost {
		b.Lost++
		return
	}
	us := rtt.Microseconds()
	if us < 0 {
		us = 0
	}
	if us > 1<<31 {
		us = 1 << 31
	}
	b.SumUS += uint64(us)
	if uint32(us) > b.MaxUS {
		b.MaxUS = uint32(us)
	}
	if b.MinUS == 0 || uint32(us) < b.MinUS {
		b.MinUS = uint32(us)
	}
}

// Point is one bucket of a series.
type Point struct {
	At      time.Time     `json:"at"`
	Samples int           `json:"samples"`
	LossPct float64       `json:"lossPct"`
	AvgRTT  time.Duration `json:"avgRtt"`
	MinRTT  time.Duration `json:"minRtt"`
	MaxRTT  time.Duration `json:"maxRtt"`
}

func (r *ring) series(now time.Time) []Point {
	oldest := now.Unix() - r.step*int64(len(r.buckets))
	var out []Point
	for _, b := range r.buckets {
		if b.Start == 0 || b.Start <= oldest || b.Start > now.Unix() || b.Samples == 0 {
			continue
		}
		p := Point{At: time.Unix(b.Start, 0).UTC(), Samples: int(b.Samples), LossPct: float64(b.Lost) * 100 / float64(b.Samples)}
		if answered := b.Samples - b.Lost; answered > 0 {
			p.AvgRTT = time.Duration(b.SumUS/uint64(answered)) * time.Microsecond
			p.MinRTT = time.Duration(b.MinUS) * time.Microsecond
			p.MaxRTT = time.Duration(b.MaxUS) * time.Microsecond
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

type deviceHistory struct {
	fine, coarse ring
	last         time.Time
}

// Quality holds the history of every device. It is safe for concurrent
// use.
type Quality struct {
	mu      sync.Mutex
	devices map[string]*deviceHistory
}

// NewQuality returns an empty history.
func NewQuality() *Quality { return &Quality{devices: map[string]*deviceHistory{}} }

// Add records one probe of device: its round trip time, or lost.
func (q *Quality) Add(device string, at time.Time, rtt time.Duration, lost bool) {
	if device == "" || len(device) > maxName {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	h, ok := q.devices[device]
	if !ok {
		if len(q.devices) >= MaxDevices {
			q.evictOldest()
		}
		h = &deviceHistory{fine: newRing(FineStep, FineBuckets), coarse: newRing(CoarseStep, CoarseBucket)}
		q.devices[device] = h
	}
	h.fine.add(at, rtt, lost)
	h.coarse.add(at, rtt, lost)
	if at.After(h.last) {
		h.last = at
	}
}

func (q *Quality) evictOldest() {
	var victim string
	var oldest time.Time
	for n, h := range q.devices {
		if victim == "" || h.last.Before(oldest) {
			victim, oldest = n, h.last
		}
	}
	delete(q.devices, victim)
}

// Forget drops a device (removed from the network).
func (q *Quality) Forget(device string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.devices, device)
}

// Series returns a device's buckets at res, oldest first.
func (q *Quality) Series(device string, res Resolution, now time.Time) ([]Point, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	h, ok := q.devices[device]
	if !ok {
		return nil, nil
	}
	switch res {
	case Fine:
		return h.fine.series(now), nil
	case Coarse:
		return h.coarse.series(now), nil
	default:
		return nil, fmt.Errorf("bilinmeyen çözünürlük %q (5m veya 1h)", res)
	}
}

// Devices lists the devices with history.
func (q *Quality) Devices() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]string, 0, len(q.devices))
	for n := range q.devices {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

type qualityFile struct {
	V       int                     `json:"v"`
	Devices map[string]qualityEntry `json:"devices"`
}

type qualityEntry struct {
	Fine   []bucket `json:"f"`
	Coarse []bucket `json:"c"`
	Last   int64    `json:"last"`
}

// Encode returns the history for saving across restarts.
func (q *Quality) Encode() ([]byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	f := qualityFile{V: 1, Devices: make(map[string]qualityEntry, len(q.devices))}
	for n, h := range q.devices {
		f.Devices[n] = qualityEntry{Fine: compact(h.fine.buckets), Coarse: compact(h.coarse.buckets), Last: h.last.Unix()}
	}
	return json.Marshal(f)
}

func compact(bs []bucket) []bucket {
	out := make([]bucket, 0, len(bs))
	for _, b := range bs {
		if b.Start != 0 {
			out = append(out, b)
		}
	}
	return out
}

// DecodeQuality reads Encode's output; buckets that do not fit the rings
// are dropped.
func DecodeQuality(data []byte) (*Quality, error) {
	if len(data) > maxDecode {
		return nil, errors.New("bağlantı kalitesi geçmişi çok büyük")
	}
	var f qualityFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("bağlantı kalitesi geçmişi okunamadı: %w", err)
	}
	if f.V != 1 {
		return nil, fmt.Errorf("bağlantı kalitesi geçmişi sürümü %d desteklenmiyor", f.V)
	}
	q := NewQuality()
	for n, e := range f.Devices {
		if n == "" || len(n) > maxName || len(q.devices) >= MaxDevices {
			continue
		}
		h := &deviceHistory{fine: newRing(FineStep, FineBuckets), coarse: newRing(CoarseStep, CoarseBucket), last: time.Unix(e.Last, 0)}
		restore(&h.fine, e.Fine)
		restore(&h.coarse, e.Coarse)
		q.devices[n] = h
	}
	return q, nil
}

func restore(r *ring, bs []bucket) {
	for _, b := range bs {
		if b.Start <= 0 || b.Start%r.step != 0 || b.Lost > b.Samples {
			continue
		}
		r.buckets[int((b.Start/r.step)%int64(len(r.buckets)))] = b
	}
}
