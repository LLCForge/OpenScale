package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/version"
)

// Device side of the membership extensions (ADR-0027, ADR-0028): following
// a root key transition, reporting the client version, leaving the network
// and the admin device's views of leave requests and clone alerts.

const (
	// rootCheckEvery is how often the coordinator's root epoch is asked
	// when nothing suggests a change.
	rootCheckEvery = 5 * time.Minute
	// versionReportEvery re-reports the version, so a restarted
	// coordinator learns it again before it asks.
	versionReportEvery = 10 * time.Minute
	// maxFetchedTransitions bounds the transitions fetched in one round.
	maxFetchedTransitions = trust.MaxRootTransitions
	// maxListed bounds the leave requests and alerts fetched.
	maxListed = 64
	// networkTransitionsFile is admin.transitionsFile in the owner's
	// network directory.
	networkTransitionsFile = "transitions.json"
)

// membershipState is guarded by its own mutex.
type membershipState struct {
	mu          sync.Mutex
	rootChecked time.Time
	versionAt   time.Time
	// rootFailed is the coordinator document digest whose transitions did
	// not apply; it is not retried until rootCheckEvery passes, so a
	// misbehaving coordinator cannot make every poll verify signatures.
	rootFailed string
}

// helloWithVersion reports the client version when due and sends hello;
// when the coordinator asks for the version (it restarted and forgot it),
// it reports and asks once more (F-027).
func (e *Engine) helloWithVersion(ctx context.Context, m control.Message) (control.Message, error) {
	e.reportVersion(ctx, false)
	resp, err := e.client.call(ctx, m)
	if err != nil && strings.Contains(err.Error(), control.ErrVersionNotReported) {
		e.reportVersion(ctx, true)
		resp, err = e.client.call(ctx, m)
	}
	return resp, err
}

func (e *Engine) reportVersion(ctx context.Context, force bool) {
	now := e.cfg.Now()
	e.member.mu.Lock()
	due := force || e.member.versionAt.IsZero() || now.Sub(e.member.versionAt) >= versionReportEvery
	e.member.mu.Unlock()
	if !due {
		return
	}
	v := version.String()
	if len(v) > control.MaxClientVersionLen {
		v = v[:control.MaxClientVersionLen]
	}
	resp, err := e.client.call(ctx, control.Message{T: control.TypeClientVersion, Data: []byte(v)})
	if (err == nil && resp.Complete) || (err != nil && err.Error() == errUnknownType) {
		e.member.mu.Lock()
		e.member.versionAt = now
		e.member.mu.Unlock()
	}
}

// syncRoot compares root epochs with the coordinator (ADR-0027). When the
// coordinator is ahead, the device fetches its transitions and document
// and applies them together; when it is behind, the device hands over its
// own transitions so the next upload is accepted. It returns true when the
// document changed.
func (e *Engine) syncRoot(ctx context.Context, hello control.Message, doc *trust.Document, digest [32]byte) (bool, error) {
	if !e.hasFeature(control.FeatureRoot) {
		return false, nil
	}
	now := e.cfg.Now()
	e.member.mu.Lock()
	due := now.Sub(e.member.rootChecked) >= rootCheckEvery
	failedBefore := e.member.rootFailed != "" && e.member.rootFailed == hello.Digest
	e.member.mu.Unlock()
	// Any document change may come with a new root (downloading needs the
	// transitions first) or follow one of ours (uploading needs the
	// coordinator on our epoch first). Documents change rarely, so one
	// extra request per change is cheap.
	docChanged := hello.Digest != hex.EncodeToString(digest[:])
	if !due && (!docChanged || failedBefore) {
		return false, nil
	}
	first, err := e.client.call(ctx, control.Message{T: control.TypeRoot})
	if err != nil {
		return false, err
	}
	e.member.mu.Lock()
	e.member.rootChecked = now
	e.member.mu.Unlock()
	mine := e.cfg.Store.Epoch()
	switch {
	case first.Version < mine:
		for _, st := range e.cfg.Store.Transitions() {
			// A transition the coordinator cannot use yet is refused; the
			// rest of the chain still goes.
			_, _ = e.client.call(ctx, control.Message{T: control.TypeRootPut, Data: st.Payload, Sig: st.Signature})
		}
		return false, nil
	case first.Version == mine:
		return false, nil
	}
	ts, err := e.fetchTransitions(ctx, first)
	if err != nil {
		return false, err
	}
	buf, err := e.fetchDocument(ctx, hello)
	if err != nil {
		return false, err
	}
	changed, err := e.cfg.Store.AcceptTransitions(ts, buf, now)
	if err != nil {
		e.member.mu.Lock()
		e.member.rootFailed = hello.Digest
		e.member.mu.Unlock()
		return false, fmt.Errorf("coordinator root transition rejected: %w", err)
	}
	if changed {
		e.logger.Info("network root key changed", "epoch", e.cfg.Store.Epoch(), "version", e.cfg.Store.Document().Version)
		return true, e.apply(ctx, e.cfg.Store.Document())
	}
	return false, nil
}

func (e *Engine) fetchTransitions(ctx context.Context, first control.Message) ([]trust.SignedRootTransition, error) {
	total := min(first.Total, maxFetchedTransitions)
	out := make([]trust.SignedRootTransition, 0, total)
	resp := first
	for off := 0; off < total; off++ {
		if off > 0 {
			var err error
			if resp, err = e.client.call(ctx, control.Message{T: control.TypeRoot, Offset: off}); err != nil {
				return nil, err
			}
		}
		if resp.T != control.TypeRoot || resp.Offset != off {
			return nil, errors.New("coordinator sent an unexpected root transition page")
		}
		out = append(out, trust.SignedRootTransition{Payload: resp.Data, Signature: resp.Sig})
	}
	return out, nil
}

// adoptLocalTransitions accepts a network directory document signed by a
// new root, with the transitions the owner's tooling stored next to it.
func (e *Engine) adoptLocalTransitions(data []byte) (bool, error) {
	raw, err := securefile.ReadLimited(filepath.Join(e.cfg.NetworkDir, networkTransitionsFile), 64<<10)
	if err != nil {
		return false, err
	}
	var f struct {
		Transitions []string `json:"transitions"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return false, errors.New("transitions.json is corrupt")
	}
	var ts []trust.SignedRootTransition
	for _, line := range f.Transitions {
		if st, err := trust.DecodeRootTransition(line); err == nil {
			ts = append(ts, st)
		}
	}
	return e.cfg.Store.AcceptTransitions(ts, data, e.cfg.Now())
}

// RequestLeave signs this device's leave request (F-106) and hands it to
// the coordinator when it supports it. It returns the request line, which
// the owner can also apply by hand, and whether the coordinator has it.
// The caller deletes the device's keys afterwards.
func (e *Engine) RequestLeave(ctx context.Context) (string, bool, error) {
	doc := e.cfg.Store.Document()
	sl, err := e.cfg.Secrets.NewLeaveRequest(trust.NewRandom(), doc.NetworkID, e.cfg.Now())
	if err != nil {
		return "", false, err
	}
	line, err := trust.EncodeLeave(sl)
	if err != nil {
		return "", false, err
	}
	if !e.hasFeature(control.FeatureLeave) {
		return line, false, nil
	}
	resp, err := e.client.call(ctx, control.Message{T: control.TypeLeave, Data: sl.Payload, Sig: sl.Signature})
	return line, err == nil && resp.Complete, nil
}

// Leaves fetches the leave requests waiting at the coordinator (admin
// devices). The results are unverified; admin.Network verifies them.
func (e *Engine) Leaves(ctx context.Context) ([]trust.SignedLeave, error) {
	var out []trust.SignedLeave
	err := e.page(ctx, control.TypeLeaves, func(resp control.Message) {
		out = append(out, trust.SignedLeave{DeviceID: resp.Target, Payload: resp.Data, Signature: resp.Sig})
	})
	return out, err
}

// CloneAlerts fetches the coordinator's clone alerts (admin devices).
func (e *Engine) CloneAlerts(ctx context.Context) ([]control.CloneAlert, error) {
	var out []control.CloneAlert
	err := e.page(ctx, control.TypeAlerts, func(resp control.Message) {
		if a, err := control.DecodeCloneAlert(resp.Data); err == nil {
			out = append(out, a)
		}
	})
	return out, err
}

// RejectPending asks the coordinator to drop one pending enrollment (F-107).
func (e *Engine) RejectPending(ctx context.Context, inviteID, deviceID string) error {
	if !e.hasFeature(control.FeatureReject) {
		return errors.New("coordinator does not support rejecting enrollments; update it")
	}
	resp, err := e.client.call(ctx, control.Message{T: control.TypeReject, Target: inviteID, Data: []byte(deviceID)})
	if err != nil {
		return err
	}
	if !resp.Complete {
		return errors.New("coordinator sent an unexpected reply")
	}
	return nil
}

// page walks a one-item-per-reply listing.
func (e *Engine) page(ctx context.Context, t string, each func(control.Message)) error {
	for offset, n := 0, 0; n < maxListed; n++ {
		resp, err := e.client.call(ctx, control.Message{T: t, Offset: offset})
		if err != nil {
			return err
		}
		if resp.T != t {
			return errors.New("coordinator sent an unexpected reply")
		}
		if offset >= resp.Total {
			return nil
		}
		if resp.Offset != offset || resp.Next != offset+1 {
			return errors.New("coordinator sent an unexpected page")
		}
		each(resp)
		offset = resp.Next
	}
	return nil
}
