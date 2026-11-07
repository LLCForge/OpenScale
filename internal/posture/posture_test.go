package posture

import (
	"net"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, r := range []Report{
		{},
		{DiskEncryption: On, Firewall: Off},
		{DiskEncryption: Off, Firewall: On, WindowsBuild: 26300},
	} {
		s := r.Encode()
		if len(s) > MaxEncoded {
			t.Fatalf("%q longer than MaxEncoded", s)
		}
		got, err := Decode(s)
		if err != nil || got != r {
			t.Fatalf("Decode(%q) = %+v, %v; want %+v", s, got, err, r)
		}
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	for _, s := range []string{
		"d=x", "d=y;d=n", "z=y", "d", "b=-1", "b=0", "b=01", "b=1000000",
		"d=y;f=y;b=26300;b=1", strings.Repeat("d=y;", 10), "d=y;f=\x1b",
	} {
		if _, err := Decode(s); err == nil {
			t.Errorf("Decode(%q) accepted", s)
		}
	}
}

func TestEvaluateFailsClosedOnUnknown(t *testing.T) {
	q := Requirement{DiskEncryption: true, Firewall: true, MinWindowsBuild: 26100}
	if got := Evaluate(q, Report{}); len(got) != 2 {
		t.Fatalf("unknown posture satisfied the requirement: %v", got)
	}
	if got := Evaluate(q, Report{DiskEncryption: On, Firewall: On, WindowsBuild: 26300}); len(got) != 0 {
		t.Fatalf("compliant posture rejected: %v", got)
	}
	if got := Evaluate(q, Report{DiskEncryption: On, Firewall: On, WindowsBuild: 19045}); len(got) != 1 {
		t.Fatalf("old build accepted: %v", got)
	}
	if got := Evaluate(Requirement{}, Report{}); len(got) != 0 {
		t.Fatalf("empty requirement failed: %v", got)
	}
}

func sysFS(rootDev string, extra fstest.MapFS) fstest.MapFS {
	m := fstest.MapFS{
		"proc/self/mountinfo": {Data: []byte("22 1 0:21 / /proc rw - proc proc rw\n25 1 " + rootDev + " / / rw,relatime - ext4 /dev/x rw\n")},
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestRootEncrypted(t *testing.T) {
	plain := sysFS("259:2", fstest.MapFS{
		"sys/class/block/nvme0n1p2/dev": {Data: []byte("259:2\n")},
		"sys/class/block/nvme0n1p1/dev": {Data: []byte("259:1\n")},
	})
	if got := rootEncrypted(plain); got != Off {
		t.Fatalf("plain partition: %v", got)
	}
	lvmOnLuks := sysFS("253:1", fstest.MapFS{
		"sys/class/block/dm-1/dev":           {Data: []byte("253:1\n")},
		"sys/class/block/dm-1/dm/uuid":       {Data: []byte("LVM-abc\n")},
		"sys/class/block/dm-1/slaves/dm-0":   {Data: nil},
		"sys/class/block/dm-0/dev":           {Data: []byte("253:0\n")},
		"sys/class/block/dm-0/dm/uuid":       {Data: []byte("CRYPT-LUKS2-0123-root\n")},
		"sys/class/block/dm-0/slaves/sda2":   {Data: nil},
		"sys/class/block/sda2/dev":           {Data: []byte("8:2\n")},
		"sys/class/block/nvme0n1p1/dev":      {Data: []byte("259:1\n")},
		"sys/class/block/dm-1/slaves/../etc": {Data: nil},
	})
	if got := rootEncrypted(lvmOnLuks); got != On {
		t.Fatalf("LVM on LUKS: %v", got)
	}
	if got := rootEncrypted(sysFS("0:31", nil)); got != Unknown {
		t.Fatalf("overlay root: %v", got)
	}
	if got := rootEncrypted(fstest.MapFS{}); got != Unknown {
		t.Fatalf("no mountinfo: %v", got)
	}
}

func TestUfwAndNft(t *testing.T) {
	if !ufwEnabled("# comment\nENABLED=yes\nLOGLEVEL=low\n") || ufwEnabled("ENABLED=no\n") {
		t.Fatal("ufw switch misread")
	}
	drop := `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
	}
	chain output {
		type filter hook output priority filter; policy accept;
	}
}`
	if got := nftInputFiltering(drop); got != On {
		t.Fatalf("policy drop: %v", got)
	}
	rejectRule := `table inet fw {
	chain in {
		type filter hook input priority 0; policy accept;
		tcp dport 22 accept
		reject with icmpx type admin-prohibited
	}
}`
	if got := nftInputFiltering(rejectRule); got != On {
		t.Fatalf("reject rule: %v", got)
	}
	open := `table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}`
	if got := nftInputFiltering(open); got != Off {
		t.Fatalf("open input: %v", got)
	}
	if got := nftInputFiltering(""); got != Off {
		t.Fatalf("empty ruleset: %v", got)
	}
}

func TestWindowsFirewallAndBitlocker(t *testing.T) {
	none := [3]int{-1, -1, -1}
	if got := windowsFirewall(none, [3]int{1, 1, 1}); got != On {
		t.Fatalf("all on: %v", got)
	}
	if got := windowsFirewall(none, [3]int{1, 0, 1}); got != Off {
		t.Fatalf("private off: %v", got)
	}
	if got := windowsFirewall([3]int{0, -1, -1}, [3]int{1, 1, 1}); got != Off {
		t.Fatalf("policy off must win: %v", got)
	}
	if got := windowsFirewall([3]int{1, 1, 1}, [3]int{0, 0, 0}); got != On {
		t.Fatalf("policy on must win: %v", got)
	}
	if got := windowsFirewall(none, [3]int{1, -1, 1}); got != Unknown {
		t.Fatalf("unreadable profile: %v", got)
	}
	for in, want := range map[string]State{"1\r\n": On, "0": Off, "2": Unknown, "": Unknown, "On": Unknown} {
		if got := bitlockerFromOutput(in); got != want {
			t.Errorf("bitlockerFromOutput(%q) = %v", in, got)
		}
	}
}

func TestMACAdvice(t *testing.T) {
	burned := net.HardwareAddr{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}
	random := net.HardwareAddr{0x3a, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}
	if Randomized(burned) || !Randomized(random) {
		t.Fatal("locally administered bit misread")
	}
	got := MACAdvice([]WiFiInterface{{Name: "Wi-Fi", MAC: burned}, {Name: "wlan1", MAC: random}, {Name: "bad", MAC: net.HardwareAddr{1}}})
	if len(got) != 1 || !strings.Contains(got[0], "Wi-Fi") {
		t.Fatalf("advice = %v", got)
	}
	for name, want := range map[string]bool{"Wi-Fi": true, "WLAN 2": true, "wlp3s0": true, "Ethernet": false, "eth0": false, "Kablosuz Ağ": true} {
		if wirelessByName(name) != want {
			t.Errorf("wirelessByName(%q) != %v", name, want)
		}
	}
}

func TestBitlockerVolumesAndDeviceEncryption(t *testing.T) {
	got := bitlockerVolumesFromOutput("C:=1\r\nd:=0\r\n=0\r\nE:=2\r\nbogus\r\nAB:=1\r\n")
	if len(got) != 3 || got["C:"] != On || got["D:"] != Off || got["E:"] != Unknown {
		t.Fatalf("volumes = %v", got)
	}
	lvmOnLuks := sysFS("253:1", fstest.MapFS{
		"sys/class/block/dm-1/dev":           {Data: []byte("253:1\n")},
		"sys/class/block/dm-1/dm/uuid":       {Data: []byte("LVM-abc\n")},
		"sys/class/block/dm-1/slaves/dm-0":   {Data: nil},
		"sys/class/block/dm-0/dev":           {Data: []byte("253:0\n")},
		"sys/class/block/dm-0/dm/uuid":       {Data: []byte("CRYPT-LUKS2-abc-luks\n")},
		"sys/class/block/nvme0n1p3/dev":      {Data: []byte("259:3\n")},
		"sys/class/block/nvme0n1p3/slaves/x": {Data: nil},
	})
	if s := DeviceEncryptedIn(lvmOnLuks, "253:1"); s != On {
		t.Fatalf("LVM on LUKS: %v", s)
	}
	if s := DeviceEncryptedIn(lvmOnLuks, "259:3"); s != Off {
		t.Fatalf("plain partition: %v", s)
	}
	if s := DeviceEncryptedIn(lvmOnLuks, "0:42"); s != Unknown {
		t.Fatalf("virtual device: %v", s)
	}
	if s := DeviceEncryptedIn(lvmOnLuks, "8:1"); s != Unknown {
		t.Fatalf("missing device: %v", s)
	}
}
