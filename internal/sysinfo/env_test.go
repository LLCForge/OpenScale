package sysinfo

import (
	"strings"
	"testing"
)

func TestVirtFromModel(t *testing.T) {
	cases := map[[2]string]string{
		{"VMware, Inc.", "VMware Virtual Platform"}:  "vmware",
		{"innotek GmbH", "VirtualBox"}:               "virtualbox",
		{"QEMU", "Standard PC (Q35 + ICH9, 2009)"}:   "kvm",
		{"Microsoft Corporation", "Virtual Machine"}: "hyperv",
		{"Microsoft Corporation", "Surface Laptop"}:  "",
		{"LENOVO", "20XW"}:                           "",
	}
	for in, want := range cases {
		if got := virtFromModel(in[0], in[1]); got != want {
			t.Errorf("%v = %q, want %q", in, got, want)
		}
	}
}

func TestJoinModel(t *testing.T) {
	if got := joinModel("LENOVO", "20XW"); got != "LENOVO 20XW" {
		t.Fatal(got)
	}
	if got := joinModel("Dell Inc.", "Dell Inc. XPS 13"); got != "Dell Inc. XPS 13" {
		t.Fatal(got)
	}
	if got := joinModel("System manufacturer", "System Product Name"); got != "" {
		t.Fatal(got)
	}
}

func TestEncodeDropsEnvironmentFirst(t *testing.T) {
	long := strings.Repeat("x", 64)
	in := Info{Version: long, OS: long, OSName: long, Arch: long, CPU: long, PublicIP: long,
		Virt: long, Model: long, Pkg: long, SSHHostKey: "SHA256:" + strings.Repeat("A", 43)}
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"md"`) {
		t.Fatalf("environment kept in an oversized report: %s", data)
	}
	small := Info{OS: "linux", Virt: "kvm", Model: "QEMU Standard PC", Pkg: "deb"}
	data, err = small.Encode()
	if err != nil || !strings.Contains(string(data), `"vm":"kvm"`) {
		t.Fatalf("%s, %v", data, err)
	}
}
