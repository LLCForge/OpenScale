package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// NextKeyFile holds the keys a device generated for a key rotation
// (ADR-0020) until the owner's new document lists them.
const NextKeyFile = "device.key.next"

// tunnelMTUFor returns the saved MTU if it is usable, else the default.
func tunnelMTUFor(st settings) int {
	if st.MTU == 0 || node.ValidateMTU(st.MTU) != nil {
		return node.DefaultMTU
	}
	return st.MTU
}

// validRelayLimits mirrors the coordinator's own check, so a bad value is
// refused when it is saved rather than when the coordinator starts.
func validRelayLimits(rate, burst int64) error {
	if rate != 0 && (rate < coordinator.MinRelayRate || rate > coordinator.MaxRelayRate) {
		return fmt.Errorf("aktarıcı hız sınırı %d ile %d bayt/sn arasında olmalı", coordinator.MinRelayRate, int64(coordinator.MaxRelayRate))
	}
	if burst != 0 && (burst < control.RelayMaxPayload || burst > coordinator.MaxRelayBurst) {
		return fmt.Errorf("aktarıcı ani yük sınırı %d ile %d bayt arasında olmalı", control.RelayMaxPayload, coordinator.MaxRelayBurst)
	}
	return nil
}

// SetAcceptNetworkDNS implements panel.App (F-065). The running tunnel
// picks the choice up within a few seconds.
func (r *Runtime) SetAcceptNetworkDNS(accept bool) error {
	if _, err := member.Open(r.path(DeviceDir)); err != nil {
		return errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	err := r.updateSettings(func(st *settings) (bool, error) {
		st.IgnoreNetworkDNS = !accept
		return true, nil
	})
	if err != nil {
		return err
	}
	r.logger.Info("network DNS choice", "accept", accept)
	return nil
}

// SetAdvanced implements panel.App: it saves the tunnel MTU, forced relay
// and the local coordinator's relay limits, then restarts what uses them.
func (r *Runtime) SetAdvanced(a panel.AdvancedSettings) error {
	_, memberErr := member.Open(r.path(DeviceDir))
	if (a.MTU != nil || a.ForceRelay != nil || advancedHasTransport(a)) && memberErr != nil {
		return errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	if (a.RelayRate != nil || a.RelayBurst != nil || advancedHasCoordinatorTCP(a)) && !r.hasCoordinator() {
		return errors.New("bu bilgisayarda koordinatör çalışmıyor")
	}
	var restartDevice, restartCoord bool
	err := r.updateSettings(func(st *settings) (bool, error) {
		next := *st
		if a.MTU != nil {
			next.MTU = *a.MTU
		}
		if a.ForceRelay != nil {
			next.ForceRelay = *a.ForceRelay
		}
		if a.RelayRate != nil {
			next.CoordinatorRelayRate = *a.RelayRate
		}
		if a.RelayBurst != nil {
			next.CoordinatorRelayBurst = *a.RelayBurst
		}
		if next.MTU != 0 {
			if err := node.ValidateMTU(next.MTU); err != nil {
				return false, err
			}
		}
		if next.ForceRelay && next.MTU > node.DefaultMTU {
			return false, fmt.Errorf("aktarıcı zorunluyken MTU en fazla %d olabilir", node.DefaultMTU)
		}
		if err := validRelayLimits(next.CoordinatorRelayRate, next.CoordinatorRelayBurst); err != nil {
			return false, err
		}
		if err := applyAdvancedTransport(&next, a); err != nil {
			return false, err
		}
		restartDevice = next.MTU != st.MTU || next.ForceRelay != st.ForceRelay ||
			next.tunnel().transportOptions != st.tunnel().transportOptions
		restartCoord = next.CoordinatorRelayRate != st.CoordinatorRelayRate || next.CoordinatorRelayBurst != st.CoordinatorRelayBurst ||
			coordinatorTCPChanged(*st, next)
		*st = next
		return restartDevice || restartCoord, nil
	})
	if err != nil {
		return err
	}
	if restartDevice && memberErr == nil {
		if st, err := r.currentSettings(); err == nil && !st.Disconnected {
			r.logger.Info("tunnel settings changed; restarting the tunnel", "mtu", st.MTU, "force_relay", st.ForceRelay)
			r.startDevice()
		}
	}
	if restartCoord {
		r.logger.Info("relay limits changed; restarting the coordinator")
		r.startCoordinator()
	}
	return nil
}

func (r *Runtime) hasCoordinator() bool {
	_, err := member.Open(r.path(CoordinatorDir))
	return err == nil
}

// networkDNSWatch keeps the network DNS settings applied for one tunnel
// run (ADR-0024).
func (r *Runtime) networkDNSWatch(store *member.Store, magic osnet.DNSConfig) DNSWatch {
	every := dnsCheckInterval
	if r.cfg.PollInterval > 0 && r.cfg.PollInterval < every {
		every = r.cfg.PollInterval
	}
	return DNSWatch{
		Magic:    magic,
		Document: store.Document,
		ExitActive: func() bool {
			r.mu.Lock()
			e := r.engine
			r.mu.Unlock()
			if e != nil {
				return e.ExitNode() != ""
			}
			// Before the engine runs, a chosen exit node counts as in use,
			// so the catch-all resolver is not set for a moment and then
			// taken away again.
			st, err := r.currentSettings()
			return err == nil && st.ExitNode != ""
		},
		Accept: func() bool {
			st, err := r.currentSettings()
			ok := err == nil && !st.IgnoreNetworkDNS
			// MagicDNS forwards to the network's resolvers only with the
			// same choice (F-065, ADR-0034).
			r.mu.Lock()
			e := r.engine
			r.mu.Unlock()
			if e != nil {
				e.SetNetworkDNSRejected(!ok)
			}
			return ok
		},
		Apply:    r.cfg.Hooks.ConfigureNetworkDNS,
		Verify:   r.cfg.Hooks.VerifyNetworkDNS,
		OnRepair: r.noteDNSRepair,
		Report: func(active bool, err error) {
			if err != nil {
				r.logger.Warn("network DNS", "error", err.Error())
			}
			r.setNetworkDNS(active, err)
		},
		Every: every,
		Now:   r.cfg.Now,
	}
}

// promoteRotatedKey switches to the keys of an approved rotation and
// returns them.
func (r *Runtime) promoteRotatedKey(store *member.Store) (*trust.DeviceSecrets, bool) {
	s, ok, err := PromoteRotatedKey(r.path(DeviceDir), store.Document())
	if err != nil {
		r.logger.Warn("device key rotation", "error", err.Error())
	}
	return s, ok
}

// PromoteRotatedKey makes the rotated keys in dir/device.key.next the
// device's keys once doc lists them (ADR-0020): the old key file is kept
// as device.key.old-<n> and the new one takes its place. It reports false
// when there is nothing to promote or doc does not list the new keys yet.
func PromoteRotatedKey(dir string, doc *trust.Document) (*trust.DeviceSecrets, bool, error) {
	nextPath := filepath.Join(dir, NextKeyFile)
	next, err := readSecrets(nextPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read rotated key: %w", err)
	}
	if _, err := selfDevice(doc, next); err != nil {
		return nil, false, nil
	}
	current := filepath.Join(dir, deviceKeyFile)
	data, err := securefile.ReadPrivate(nextPath, trust.MaxDeviceKeySize)
	if err != nil {
		return nil, false, err
	}
	defer wipe(data)
	for i := 1; i <= maxOldKeys; i++ {
		old := filepath.Join(dir, fmt.Sprintf("%s.old-%d", deviceKeyFile, i))
		if _, err := os.Stat(old); err == nil {
			continue
		}
		if err := os.Rename(current, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, false, fmt.Errorf("keep old key: %w", err)
		}
		if err := securefile.WriteNew(current, data); err != nil {
			// Put the old key back so the device keeps a key file.
			_ = os.Rename(old, current)
			return nil, false, fmt.Errorf("write rotated key: %w", err)
		}
		if err := os.Remove(nextPath); err != nil {
			return nil, false, fmt.Errorf("remove rotated key file: %w", err)
		}
		return next, true, nil
	}
	return nil, false, errors.New("too many old key files; remove old device.key.old-* files")
}

// maxOldKeys bounds the kept old key files.
const maxOldKeys = 100
