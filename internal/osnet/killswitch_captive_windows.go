//go:build windows && (amd64 || arm64)

package osnet

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Captive portal exception on Windows (#85). The permits are added in a
// dynamic WFP session: Windows deletes them by itself when the session
// closes, which happens when the time is up, when the owner ends the
// exception, and when the process that opened it exits or crashes. So a
// forgotten or crashed exception never stays open.

// fwpmSessionFlagDynamic is FWPM_SESSION_FLAG_DYNAMIC.
const fwpmSessionFlagDynamic = 0x1

var captiveWin struct {
	mu    sync.Mutex
	h     windows.Handle
	gen   uint64
	timer *time.Timer
}

// AllowCaptivePortal permits HTTP and HTTPS to the given local gateway
// addresses for d while the kill switch is installed. The exception lives
// as long as this process does, at most d.
func AllowCaptivePortal(addrs []netip.Addr, d time.Duration) error {
	addrs, err := validCaptive(addrs, d)
	if err != nil {
		return err
	}
	on, err := KillSwitchInstalled()
	if err != nil {
		return err
	}
	if !on {
		return ErrKillSwitchNotInstalled
	}
	captiveWin.mu.Lock()
	defer captiveWin.mu.Unlock()
	closeCaptiveLocked()
	h, err := openDynamicEngine()
	if err != nil {
		return err
	}
	if err := wfpCall(procFwpmTransactionBegin0, uintptr(h), 0); err != nil {
		closeEngine(h)
		return wfpError("WFP işlemi başlatılamadı", err)
	}
	for _, r := range captivePlan(addrs) {
		if err := addCaptiveRule(h, r); err != nil {
			_ = wfpCall(procFwpmTransactionAbort0, uintptr(h))
			closeEngine(h)
			return fmt.Errorf("giriş sayfası istisnası eklenemedi: %w", err)
		}
	}
	if err := wfpCall(procFwpmTransactionCommit0, uintptr(h)); err != nil {
		_ = wfpCall(procFwpmTransactionAbort0, uintptr(h))
		closeEngine(h)
		return wfpError("WFP işlemi tamamlanamadı", err)
	}
	captiveWin.gen++
	gen := captiveWin.gen
	captiveWin.h = h
	captiveWin.timer = time.AfterFunc(d, func() {
		captiveWin.mu.Lock()
		defer captiveWin.mu.Unlock()
		if captiveWin.gen == gen {
			closeCaptiveLocked()
		}
	})
	return nil
}

// RevokeCaptivePortal ends this process's captive portal exception.
func RevokeCaptivePortal() error {
	captiveWin.mu.Lock()
	defer captiveWin.mu.Unlock()
	closeCaptiveLocked()
	return nil
}

func closeCaptiveLocked() {
	if captiveWin.timer != nil {
		captiveWin.timer.Stop()
		captiveWin.timer = nil
	}
	if captiveWin.h != 0 {
		closeEngine(captiveWin.h)
		captiveWin.h = 0
	}
}

func openDynamicEngine() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("OpenScale giriş sayfası istisnası")
	if err != nil {
		return 0, err
	}
	session := &fwpmSession0{
		displayData:          fwpmDisplayData0{name: name},
		flags:                fwpmSessionFlagDynamic,
		txnWaitTimeoutInMSec: ksTxnWaitMillis,
	}
	var h windows.Handle
	err = wfpCall(procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(session)
	runtime.KeepAlive(name)
	if err != nil {
		return 0, wfpError("Windows Filtering Platform açılamadı", err)
	}
	return h, nil
}

// addCaptiveRule adds one non-persistent permit in OpenScale's persistent
// sublayer; BFE generates its key.
func addCaptiveRule(h windows.Handle, r ksRule) error {
	if r.IPv6 || r.Inbound || !r.Permit || r.Kind != ksMatchRemotePrefixPort || r.Protocol != protoTCP {
		return errors.New("geçersiz giriş sayfası kuralı")
	}
	b := &wfpBuilder{}
	addr, err := b.prefixValue(r)
	if err != nil {
		return err
	}
	conds := []fwpmFilterCondition0{
		{fieldKey: condIPRemoteAddress, matchType: fwpMatchEqual, conditionValue: addr},
		{fieldKey: condIPProtocol, matchType: fwpMatchEqual, conditionValue: fwpValue0{typ: fwpUint8, value: uintptr(r.Protocol)}},
		{fieldKey: condIPRemotePort, matchType: fwpMatchEqual, conditionValue: b.uint16Value(r.RemotePort)},
	}
	name, err := windows.UTF16PtrFromString("OpenScale: " + r.Name)
	if err != nil {
		return err
	}
	f := &fwpmFilter0{
		displayData:         fwpmDisplayData0{name: name},
		providerKey:         &ksProviderKey,
		layerKey:            layerALEAuthConnectV4,
		subLayerKey:         ksSublayerKey,
		weight:              fwpValue0{typ: fwpUint8, value: uintptr(r.Weight)},
		action:              fwpmAction0{typ: fwpActionPermit},
		numFilterConditions: uint32(len(conds)),
		filterCondition:     &conds[0],
	}
	var id uint64
	err = wfpCall(procFwpmFilterAdd0, uintptr(h), uintptr(unsafe.Pointer(f)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(f)
	runtime.KeepAlive(conds)
	runtime.KeepAlive(b)
	runtime.KeepAlive(name)
	if err != nil {
		return wfpError("WFP", err)
	}
	return nil
}

// RestoreKillSwitch has nothing to do on Windows: the WFP filters are
// persistent and already active at boot (#74).
func RestoreKillSwitch() (bool, error) { return false, nil }

// KillSwitchBootSupported is false on Windows: no boot unit is needed,
// the filters themselves survive a restart.
func KillSwitchBootSupported() bool { return false }

// EnableKillSwitchBoot is not needed on Windows.
func EnableKillSwitchBoot(string) error {
	return errors.New("Windows'ta kill switch filtreleri kalıcıdır ve açılışta zaten etkindir")
}

// DisableKillSwitchBoot has nothing to remove on Windows.
func DisableKillSwitchBoot() error { return nil }

// KillSwitchBootEnabled reports whether the persistent filters are in
// place, since on Windows they are what protects the boot.
func KillSwitchBootEnabled() (bool, error) { return KillSwitchInstalled() }
