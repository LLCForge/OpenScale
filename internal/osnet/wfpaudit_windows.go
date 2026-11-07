//go:build windows

package osnet

import (
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Third-party filters that can defeat the kill switch (#499, ADR-0154).
//
// WFP evaluates every sublayer from the highest weight down; a block wins
// over a permit unless the permit cleared the "action write" right in a
// sublayer evaluated earlier (a hard permit), and a callout can decide
// anything. OpenScale's sublayer has the highest weight (0xffff), so only
// another sublayer with the same weight can be evaluated first, in an
// order WFP does not define. This audit only reads: it lists such
// sublayers and the hard permits and callouts they hold on the four
// layers the kill switch uses. It needs the rights of the service.

var (
	procFwpmSubLayerCreateEnumHandle0  = modfwpuclnt.NewProc("FwpmSubLayerCreateEnumHandle0")
	procFwpmSubLayerEnum0              = modfwpuclnt.NewProc("FwpmSubLayerEnum0")
	procFwpmSubLayerDestroyEnumHandle0 = modfwpuclnt.NewProc("FwpmSubLayerDestroyEnumHandle0")
)

// FWP_ACTION_TYPE values with the callout flag (0x4000).
const (
	fwpActionFlagCallout = 0x4000
	wfpAuditMaxSublayers = 4096
	wfpAuditMaxFilters   = 1 << 16
)

// WFPRisk is one configuration that could let traffic past the kill
// switch.
type WFPRisk struct {
	// Level is "high" for a hard permit or callout in a sublayer that
	// may be evaluated before OpenScale's, "info" for an equal-weight
	// sublayer without such filters.
	Level   string `json:"level"`
	Message string `json:"message"`
}

type wfpSublayerInfo struct {
	key    windows.GUID
	name   string
	weight uint16
}

// KillSwitchBypassRisks lists the third-party WFP objects that may be
// evaluated before the kill switch and permit what it blocks.
func KillSwitchBypassRisks() ([]WFPRisk, error) {
	h, err := openEngine()
	if err != nil {
		return nil, err
	}
	defer closeEngine(h)
	subs, err := enumSublayers(h)
	if err != nil {
		return nil, wfpError("WFP alt katmanları okunamadı", err)
	}
	rivals := map[windows.GUID]wfpSublayerInfo{}
	for _, s := range subs {
		if s.key != ksSublayerKey && s.weight >= ksSublayerWeight {
			rivals[s.key] = s
		}
	}
	var out []WFPRisk
	risky := map[windows.GUID]int{}
	for _, layer := range ksLayers {
		filters, err := enumLayerFilters(h, layer)
		if err != nil {
			return nil, wfpError("WFP kuralları okunamadı", err)
		}
		for _, f := range filters {
			if _, ok := rivals[f.sublayer]; !ok {
				continue
			}
			hardPermit := f.action == fwpActionPermit && f.flags&fwpmFilterFlagClearActionRight != 0
			callout := f.action&fwpActionFlagCallout != 0
			if !hardPermit && !callout {
				continue
			}
			risky[f.sublayer]++
			kind := "kesin izin (hard permit)"
			if callout {
				kind = "çağrı (callout)"
			}
			out = append(out, WFPRisk{Level: "high", Message: fmt.Sprintf("%q alt katmanında %q kuralı bir %s; kill switch engelinden önce değerlendirilebilir", rivals[f.sublayer].name, f.name, kind)})
		}
	}
	for key, s := range rivals {
		if risky[key] == 0 {
			out = append(out, WFPRisk{Level: "info", Message: fmt.Sprintf("%q alt katmanı OpenScale ile aynı en yüksek ağırlıkta; şu an kill switch katmanlarında kesin izni yok", s.name)})
		}
	}
	return out, nil
}

func enumSublayers(h windows.Handle) ([]wfpSublayerInfo, error) {
	var eh windows.Handle
	if err := wfpCall(procFwpmSubLayerCreateEnumHandle0, uintptr(h), 0, uintptr(unsafe.Pointer(&eh))); err != nil {
		return nil, err
	}
	defer func() { _ = wfpCall(procFwpmSubLayerDestroyEnumHandle0, uintptr(h), uintptr(eh)) }()
	var out []wfpSublayerInfo
	for len(out) < wfpAuditMaxSublayers {
		var entries **fwpmSublayer0
		var n uint32
		if err := wfpCall(procFwpmSubLayerEnum0, uintptr(h), uintptr(eh), ksEnumBatch, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n))); err != nil {
			return nil, err
		}
		if n == 0 || entries == nil {
			return out, nil
		}
		for _, s := range unsafe.Slice(entries, n) {
			if s != nil {
				out = append(out, wfpSublayerInfo{key: s.subLayerKey, name: wfpName(s.displayData, s.subLayerKey), weight: s.weight})
			}
		}
		freeWFP(unsafe.Pointer(&entries))
		if n < ksEnumBatch {
			return out, nil
		}
	}
	return out, nil
}

type wfpFilterInfo struct {
	sublayer windows.GUID
	name     string
	action   uint32
	flags    uint32
}

// enumLayerFilters lists every filter of one layer, of any provider.
func enumLayerFilters(h windows.Handle, layer windows.GUID) ([]wfpFilterInfo, error) {
	tmpl := &fwpmFilterEnumTemplate0{
		layerKey:   layer,
		enumType:   fwpFilterEnumOverlapping,
		actionMask: 0xffffffff,
	}
	var eh windows.Handle
	err := wfpCall(procFwpmFilterCreateEnumHandle0, uintptr(h), uintptr(unsafe.Pointer(tmpl)), uintptr(unsafe.Pointer(&eh)))
	runtime.KeepAlive(tmpl)
	if err != nil {
		return nil, err
	}
	defer func() { _ = wfpCall(procFwpmFilterDestroyEnumHandle0, uintptr(h), uintptr(eh)) }()
	var out []wfpFilterInfo
	for len(out) < wfpAuditMaxFilters {
		var entries **fwpmFilter0
		var n uint32
		if err := wfpCall(procFwpmFilterEnum0, uintptr(h), uintptr(eh), ksEnumBatch, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n))); err != nil {
			return nil, err
		}
		if n == 0 || entries == nil {
			return out, nil
		}
		for _, f := range unsafe.Slice(entries, n) {
			if f != nil {
				out = append(out, wfpFilterInfo{sublayer: f.subLayerKey, name: wfpName(f.displayData, f.filterKey), action: f.action.typ, flags: f.flags})
			}
		}
		freeWFP(unsafe.Pointer(&entries))
		if n < ksEnumBatch {
			return out, nil
		}
	}
	return out, nil
}

// maxWFPName bounds a display name taken from another program.
const maxWFPName = 128

func wfpName(d fwpmDisplayData0, key windows.GUID) string {
	name := ""
	if d.name != nil {
		name = windows.UTF16PtrToString(d.name)
	}
	name = cleanWFPName(name)
	if name == "" {
		return key.String()
	}
	return name
}

// cleanWFPName drops control characters and invalid UTF-8 from a name
// another program chose.
func cleanWFPName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxWFPName {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
