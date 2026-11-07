package rdesk

import (
	"slices"
	"sync"
	"time"
)

// maxLiveAnnotations bounds the marks an overlay keeps; the oldest go
// first.
const maxLiveAnnotations = 256

// AnnotationSet keeps the marks an overlay draws (#425): Apply adds a mark
// or clears a session's marks, Active returns the unexpired ones. It is
// safe for concurrent use; the platform overlay redraws from Active.
type AnnotationSet struct {
	mu    sync.Mutex
	items []Annotation
}

// Apply records a mark from AnnotateFunc.
func (s *AnnotationSet) Apply(a Annotation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.Kind == AnnotateClear {
		s.items = slices.DeleteFunc(s.items, func(x Annotation) bool { return x.Session == a.Session })
		return
	}
	a.Points = slices.Clone(a.Points)
	s.items = append(s.items, a)
	if n := len(s.items) - maxLiveAnnotations; n > 0 {
		s.items = slices.Delete(s.items, 0, n)
	}
}

// Active drops expired marks and returns a copy of the rest, oldest first.
func (s *AnnotationSet) Active(now time.Time) []Annotation {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = slices.DeleteFunc(s.items, func(x Annotation) bool { return !now.Before(x.Expires) })
	return slices.Clone(s.items)
}
