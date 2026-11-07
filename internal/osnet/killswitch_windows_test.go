//go:build windows && (amd64 || arm64)

package osnet

import (
	"net/netip"
	"testing"
	"unsafe"
)

// The expected sizes and offsets are those of the 64-bit Windows SDK
// headers (fwptypes.h, fwpmtypes.h). A wrong layout would make BFE read
// garbage, so it is pinned here; the real API is never called in tests.
func TestWFPStructLayout(t *testing.T) {
	check := func(name string, got, want uintptr) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
	check("sizeof(FWP_BYTE_BLOB)", unsafe.Sizeof(fwpByteBlob{}), 16)
	check("sizeof(FWPM_DISPLAY_DATA0)", unsafe.Sizeof(fwpmDisplayData0{}), 16)
	check("sizeof(FWP_VALUE0)", unsafe.Sizeof(fwpValue0{}), 16)
	check("sizeof(FWP_RANGE0)", unsafe.Sizeof(fwpRange0{}), 32)
	check("sizeof(FWP_V4_ADDR_AND_MASK)", unsafe.Sizeof(fwpV4AddrAndMask{}), 8)
	check("sizeof(FWP_V6_ADDR_AND_MASK)", unsafe.Sizeof(fwpV6AddrAndMask{}), 17)
	check("sizeof(FWPM_FILTER_CONDITION0)", unsafe.Sizeof(fwpmFilterCondition0{}), 40)
	check("sizeof(FWPM_ACTION0)", unsafe.Sizeof(fwpmAction0{}), 20)
	check("sizeof(FWPM_SESSION0)", unsafe.Sizeof(fwpmSession0{}), 72)
	check("sizeof(FWPM_PROVIDER0)", unsafe.Sizeof(fwpmProvider0{}), 64)
	check("sizeof(FWPM_SUBLAYER0)", unsafe.Sizeof(fwpmSublayer0{}), 72)
	check("sizeof(FWPM_FILTER0)", unsafe.Sizeof(fwpmFilter0{}), 200)
	check("sizeof(FWPM_FILTER_ENUM_TEMPLATE0)", unsafe.Sizeof(fwpmFilterEnumTemplate0{}), 72)

	var c fwpmFilterCondition0
	check("FWPM_FILTER_CONDITION0.matchType", unsafe.Offsetof(c.matchType), 16)
	check("FWPM_FILTER_CONDITION0.conditionValue", unsafe.Offsetof(c.conditionValue), 24)

	var s fwpmSession0
	check("FWPM_SESSION0.flags", unsafe.Offsetof(s.flags), 32)
	check("FWPM_SESSION0.txnWaitTimeoutInMSec", unsafe.Offsetof(s.txnWaitTimeoutInMSec), 36)
	check("FWPM_SESSION0.processId", unsafe.Offsetof(s.processID), 40)
	check("FWPM_SESSION0.sid", unsafe.Offsetof(s.sid), 48)
	check("FWPM_SESSION0.kernelMode", unsafe.Offsetof(s.kernelMode), 64)

	var p fwpmProvider0
	check("FWPM_PROVIDER0.flags", unsafe.Offsetof(p.flags), 32)
	check("FWPM_PROVIDER0.providerData", unsafe.Offsetof(p.providerData), 40)
	check("FWPM_PROVIDER0.serviceName", unsafe.Offsetof(p.serviceName), 56)

	var sl fwpmSublayer0
	check("FWPM_SUBLAYER0.providerKey", unsafe.Offsetof(sl.providerKey), 40)
	check("FWPM_SUBLAYER0.providerData", unsafe.Offsetof(sl.providerData), 48)
	check("FWPM_SUBLAYER0.weight", unsafe.Offsetof(sl.weight), 64)

	var f fwpmFilter0
	check("FWPM_FILTER0.displayData", unsafe.Offsetof(f.displayData), 16)
	check("FWPM_FILTER0.flags", unsafe.Offsetof(f.flags), 32)
	check("FWPM_FILTER0.providerKey", unsafe.Offsetof(f.providerKey), 40)
	check("FWPM_FILTER0.providerData", unsafe.Offsetof(f.providerData), 48)
	check("FWPM_FILTER0.layerKey", unsafe.Offsetof(f.layerKey), 64)
	check("FWPM_FILTER0.subLayerKey", unsafe.Offsetof(f.subLayerKey), 80)
	check("FWPM_FILTER0.weight", unsafe.Offsetof(f.weight), 96)
	check("FWPM_FILTER0.numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112)
	check("FWPM_FILTER0.filterCondition", unsafe.Offsetof(f.filterCondition), 120)
	check("FWPM_FILTER0.action", unsafe.Offsetof(f.action), 128)
	check("FWPM_FILTER0.providerContextKey", unsafe.Offsetof(f.providerContext), 152)
	check("FWPM_FILTER0.reserved", unsafe.Offsetof(f.reserved), 168)
	check("FWPM_FILTER0.filterId", unsafe.Offsetof(f.filterID), 176)
	check("FWPM_FILTER0.effectiveWeight", unsafe.Offsetof(f.effectiveWeight), 184)

	var e fwpmFilterEnumTemplate0
	check("FWPM_FILTER_ENUM_TEMPLATE0.layerKey", unsafe.Offsetof(e.layerKey), 8)
	check("FWPM_FILTER_ENUM_TEMPLATE0.enumType", unsafe.Offsetof(e.enumType), 24)
	check("FWPM_FILTER_ENUM_TEMPLATE0.providerContextTemplate", unsafe.Offsetof(e.providerContextTemplate), 32)
	check("FWPM_FILTER_ENUM_TEMPLATE0.numFilterConditions", unsafe.Offsetof(e.numFilterConditions), 40)
	check("FWPM_FILTER_ENUM_TEMPLATE0.filterCondition", unsafe.Offsetof(e.filterCondition), 48)
	check("FWPM_FILTER_ENUM_TEMPLATE0.actionMask", unsafe.Offsetof(e.actionMask), 56)
	check("FWPM_FILTER_ENUM_TEMPLATE0.calloutKey", unsafe.Offsetof(e.calloutKey), 64)
}

func TestFilterKeysAreDistinctAndFixed(t *testing.T) {
	seen := map[[16]byte]bool{}
	for i := range maxKillSwitchFilters {
		k := ksFilterKey(i)
		if k.Data1 != ksFilterKeyBase.Data1 || k.Data2 != ksFilterKeyBase.Data2 || k.Data3 != ksFilterKeyBase.Data3 {
			t.Fatalf("key %d left the base GUID", i)
		}
		b := *(*[16]byte)(unsafe.Pointer(&k))
		if seen[b] {
			t.Fatalf("filter key %d repeats", i)
		}
		seen[b] = true
	}
	if ksFilterKey(3) != ksFilterKey(3) {
		t.Fatal("filter keys must be deterministic")
	}
	for _, g := range [][16]byte{*(*[16]byte)(unsafe.Pointer(&ksProviderKey)), *(*[16]byte)(unsafe.Pointer(&ksSublayerKey))} {
		if seen[g] {
			t.Fatal("provider or sublayer key collides with a filter key")
		}
	}
}

func TestLayerSelection(t *testing.T) {
	cases := map[[2]bool]interface{ String() string }{
		{false, false}: layerALEAuthConnectV4,
		{false, true}:  layerALEAuthRecvAcceptV4,
		{true, false}:  layerALEAuthConnectV6,
		{true, true}:   layerALEAuthRecvAcceptV6,
	}
	for k, want := range cases {
		if got := ksLayer(ksRule{IPv6: k[0], Inbound: k[1]}); got.String() != want.String() {
			t.Fatalf("v6=%v inbound=%v: layer %s, want %s", k[0], k[1], got, want)
		}
	}
}

// The condition translation runs without touching WFP.
func TestConditionTranslation(t *testing.T) {
	b := &wfpBuilder{}
	blob := &fwpByteBlob{}
	for _, r := range killSwitchPlan(true, true) {
		conds, err := b.conditions(r, 0x1234, blob)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		switch r.Kind {
		case ksMatchAll:
			if len(conds) != 0 {
				t.Fatalf("default block must have no conditions")
			}
		case ksMatchRemotePrefixPort, ksMatchICMPTypes:
			if len(conds) != 2 {
				t.Fatalf("%s: %d conditions", r.Name, len(conds))
			}
		case ksMatchUDPPorts:
			if len(conds) != 3 {
				t.Fatalf("%s: %d conditions", r.Name, len(conds))
			}
		default:
			if len(conds) != 1 {
				t.Fatalf("%s: %d conditions", r.Name, len(conds))
			}
		}
	}
	if _, err := b.conditions(ksRule{Kind: ksMatchTunnel}, 0, blob); err == nil {
		t.Fatal("a tunnel permit without an interface must fail")
	}
	if _, err := b.conditions(ksRule{Kind: ksMatchApp}, 1, nil); err == nil {
		t.Fatal("a program permit without an app id must fail")
	}
	if _, err := b.conditions(ksRule{Kind: ksMatchRemotePrefix, IPv6: true, Prefix: netip.MustParsePrefix("10.0.0.0/8")}, 1, blob); err == nil {
		t.Fatal("an IPv4 prefix on an IPv6 layer must fail")
	}
	if _, err := b.conditions(ksRule{Kind: ksMatchKind(200)}, 1, blob); err == nil {
		t.Fatal("unknown rule kinds must fail")
	}
}

func TestV4MaskIsHostOrder(t *testing.T) {
	b := &wfpBuilder{}
	v, err := b.prefixValue(ksRule{Prefix: netip.MustParsePrefix("172.16.0.0/12")})
	if err != nil {
		t.Fatal(err)
	}
	if v.typ != fwpV4AddrMask {
		t.Fatalf("type %#x", v.typ)
	}
	m := b.keep[len(b.keep)-1].(*fwpV4AddrAndMask)
	if m.addr != 0xac100000 || m.mask != 0xfff00000 {
		t.Fatalf("addr %#x mask %#x", m.addr, m.mask)
	}
	v6, err := b.prefixValue(ksRule{IPv6: true, Prefix: netip.MustParsePrefix("fe80::/10")})
	if err != nil || v6.typ != fwpV6AddrMask {
		t.Fatalf("v6 prefix: %v", err)
	}
	m6 := b.keep[len(b.keep)-1].(*fwpV6AddrAndMask)
	if m6.prefixLength != 10 || m6.addr[0] != 0xfe || m6.addr[1] != 0x80 {
		t.Fatalf("v6 value %+v", m6)
	}
}
