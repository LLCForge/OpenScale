package trust

import (
	"errors"
	"math"
	"slices"
	"testing"
	"time"
)

// A scoped administrator must not be able to push members past every version
// the root can sign (audit: trust/g1_admin_grant.verifyAdminDocument/
// unbounded-admin-version).
func TestAdminCannotBlockRootWithHugeVersion(t *testing.T) {
	a := newAdminFixture(t, []AdminOp{AdminOpSSHCert}, nil)
	st := &State{Anchor: a.anchor}
	now := testNow.Add(2 * time.Hour)
	if _, err := st.Accept(a.base, now); err != nil {
		t.Fatal(err)
	}
	huge := a.next(t, func(d *Document) { d.Version = math.MaxUint64 })
	if _, err := st.Accept(a.signAdmin(t, huge), now); !errors.Is(err, ErrAdminBase) {
		t.Fatalf("huge administrator version: got %v, want ErrAdminBase", err)
	}
	if st.HighestVersion != a.baseDoc.Version {
		t.Fatalf("state moved to %d", st.HighestVersion)
	}
	// The root's revocation still reaches this member.
	revoke, err := a.baseDoc.Next(testNow.Add(time.Hour), DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := revoke.RevokeAdmin(a.grant.Grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(a.sign(t, revoke), now); err != nil {
		t.Fatalf("root revocation refused: %v", err)
	}
}

// The bound itself: the last allowed version passes, the next is refused, and
// the root's overtaking version beats the highest one an administrator can
// reach on that base.
func TestAdminVersionBoundAndRootOvertake(t *testing.T) {
	a := newAdminFixture(t, []AdminOp{AdminOpRules}, nil)
	now := testNow.Add(2 * time.Hour)
	st := &State{Anchor: a.anchor}
	over := a.next(t, func(d *Document) { d.Version = a.baseDoc.Version + MaxAdminVersionStep + 1 })
	if _, err := st.Accept(a.signAdmin(t, over), now); !errors.Is(err, ErrAdminBase) {
		t.Fatalf("one above the bound: got %v, want ErrAdminBase", err)
	}
	top := a.next(t, func(d *Document) { d.Version = a.baseDoc.Version + MaxAdminVersionStep })
	if _, err := st.Accept(a.signAdmin(t, top), now); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	revoke, err := a.baseDoc.Next(testNow.Add(time.Hour), DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	// A plain next version is below the administrator's, as before.
	if err := revoke.RevokeAdmin(a.grant.Grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(a.sign(t, revoke), now); !errors.Is(err, ErrRollback) {
		t.Fatalf("plain next version: got %v, want ErrRollback", err)
	}
	revoke.Version = RootOvertakeVersion(a.baseDoc.Version)
	if _, err := st.Accept(a.sign(t, revoke), now); err != nil {
		t.Fatalf("overtaking root version refused: %v", err)
	}
	if !slices.Contains(st.RevokedAdmins, a.grant.Grant.ID) {
		t.Fatal("the member did not adopt the revocation")
	}
	if got := RootOvertakeVersion(math.MaxUint64 - 1); got != math.MaxUint64 {
		t.Fatalf("overtake does not saturate: %d", got)
	}
}
