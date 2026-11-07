package trust

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestSyncRuleValidation(t *testing.T) {
	_, doc := policyDoc(t)
	bad := []Rule{
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Folders: []string{"Belgeler"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Folders: []string{"-a"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Folders: []string{"a", "a"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Folders: []string{"a"}, Quota: 1 << 30},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Folders: []string{"a"}, AllowPrune: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Backup: true, Quota: 10},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Backup: true, Quota: -1},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Backup: true, Users: []string{"ali"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Backup: true, AllowControl: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Backup: true, Protocol: ProtocolTCP, Ports: []string{"4050"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Action: RuleDeny, Backup: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceFiles, Folders: []string{"a"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, Backup: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Backup: true},
	}
	n := len(doc.Rules)
	for i, r := range bad {
		if err := doc.AddRule(r); err == nil {
			t.Errorf("rule %d should be rejected: %+v", i, r)
		}
	}
	if len(doc.Rules) != n {
		t.Fatal("rejected rules must not be kept")
	}
	if ServiceSync.Port() != SyncPort || SyncPort != 4050 || !slices.Contains(Services(), ServiceSync) {
		t.Fatal("sync service registration")
	}
	if !ValidSyncFolderID("a") || !ValidSyncFolderID("foto-2026") || ValidSyncFolderID(strings.Repeat("a", 64)) || ValidSyncFolderID("a_b") {
		t.Fatal("folder id check")
	}
}

func TestSyncAccess(t *testing.T) {
	_, doc := policyDoc(t)
	rules := []Rule{
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Folders: []string{"belgeler", "foto"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSync, Folders: []string{"belgeler"}, Backup: true, Quota: 2 << 30},
		{From: []string{"telefon"}, To: []string{"vps"}, Service: ServiceSync, Backup: true, AllowPrune: true},
		{From: []string{"telefon"}, To: []string{"masaustu"}, Service: ServiceSync, Folders: []string{"muzik"}},
		{From: []string{"telefon"}, To: []string{"masaustu"}, Service: ServiceSync, Action: RuleDeny},
	}
	for i, r := range rules {
		if err := doc.AddRule(r); err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
	}
	if !doc.AllowsSyncFolder("laptop", "vps", "foto") || doc.AllowsSyncFolder("laptop", "vps", "muzik") {
		t.Fatal("folder grant")
	}
	if doc.AllowsSyncFolder("vps", "laptop", "foto") {
		t.Fatal("sync must not be symmetric: the rule lets laptop read vps, not the other way")
	}
	if doc.AllowsSyncFolder("telefon", "masaustu", "muzik") {
		t.Fatal("deny rule must win")
	}
	g := doc.SyncAccess("laptop", "vps")
	if !slices.Equal(g.Folders, []string{"belgeler", "foto"}) || !g.Backup || g.Quota != 2<<30 || g.AllowPrune {
		t.Fatalf("laptop grant: %+v", g)
	}
	g = doc.SyncAccess("telefon", "vps")
	if len(g.Folders) != 0 || !g.Backup || g.Quota != DefaultBackupQuota || !g.AllowPrune {
		t.Fatalf("telefon grant: %+v", g)
	}
	if !doc.AllowsBackup("telefon", "vps") || doc.AllowsBackup("telefon", "masaustu") {
		t.Fatal("backup grant")
	}
	if g := doc.SyncAccess("telefon", "masaustu"); len(g.Folders) != 0 || g.Backup {
		t.Fatalf("denied grant: %+v", g)
	}
	if !doc.HostsService("vps", ServiceSync) || doc.HostsService("laptop", ServiceSync) {
		t.Fatal("hosts service")
	}
}

// TestSyncFieldsEncodeOnlyWhenSet keeps documents without sync rules
// byte-for-byte as before.
func TestSyncFieldsEncodeOnlyWhenSet(t *testing.T) {
	plain, err := json.Marshal(Rule{From: []string{"a"}, To: []string{"b"}, Service: ServiceFiles})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"folders", "backup", "quota", "allow_prune"} {
		if strings.Contains(string(plain), k) {
			t.Fatalf("%s must be omitted: %s", k, plain)
		}
	}
	withSync, _ := json.Marshal(Rule{From: []string{"a"}, To: []string{"b"}, Service: ServiceSync, Folders: []string{"x"}, Backup: true, Quota: 1 << 30, AllowPrune: true})
	for _, k := range []string{`"folders":["x"]`, `"backup":true`, `"quota":1073741824`, `"allow_prune":true`} {
		if !strings.Contains(string(withSync), k) {
			t.Fatalf("missing %s: %s", k, withSync)
		}
	}
}
