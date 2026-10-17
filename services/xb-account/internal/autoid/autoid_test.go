package autoid

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"openpak/xb-live/internal/xbaccountapi"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
	"openpak/xb-live/services/xb-account/internal/coretest"
	"openpak/xb-live/services/xb-account/internal/store"
)

func setup(t *testing.T) (*Service, *coretest.Core, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "x.db"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := coretest.New()
	return &Service{Core: c, Store: db}, c, db
}

func TestGamertagDerivation(t *testing.T) {
	for in, want := range map[string]string{
		"linkcheck":            "linkcheck",
		"  Tobias  Fernandes ": "Tobias Fernande",
		"a_very-long.display name that overflows": "a very long disp",
		"1234": "Player1234",
		"日本語":  "Player",
		"x":    "x",
	} {
		got := Gamertag(in, "acct", 0)
		if len(got) > 15 || !xbaccountapi.ValidGamertag(got) {
			t.Fatalf("%q -> %q not a valid gamertag", in, got)
		}
		if want != "a very long disp" && got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
	}
	a, b := Gamertag("Same Name Long Long", "a", 1), Gamertag("Same Name Long Long", "b", 1)
	if a == b || len(a) > 15 || !xbaccountapi.ValidGamertag(a) {
		t.Fatalf("suffixes %q %q", a, b)
	}
	if Gamertag("Same", "a", 2) != Gamertag("Same", "a", 2) {
		t.Fatal("suffix must be stable")
	}
}

func TestEnsureIsDeterministicIdempotentAndRaceSafe(t *testing.T) {
	s, c, db := setup(t)
	ctx := context.Background()
	c.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	var wg sync.WaitGroup
	created := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.Ensure(ctx, "acct1")
			if err != nil {
				t.Error(err)
			}
			created <- ok
		}()
	}
	wg.Wait()
	close(created)
	n := 0
	for ok := range created {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d goroutines created the identity", n)
	}
	u, ok, err := db.ActiveUserOf(ctx, "acct1")
	if err != nil || !ok || u.XUID != XUID("acct1", 0) || u.Gamertag != "name acct1" || !strings.HasPrefix(u.XUID, "0009") {
		t.Fatalf("user %+v %v %v", u, ok, err)
	}
	if l, err := c.GetActiveLinkByAccount(ctx, "acct1"); err != nil || l.SubjectID != u.XUID || l.PublicCode != u.Gamertag {
		t.Fatalf("link %+v %v", l, err)
	}
	if _, err := db.GetDevice(ctx, "0000000000000001"); err == nil {
		t.Fatal("an automatic identity must not create a device")
	}
	if again, err := s.Ensure(ctx, "acct1"); again || err != nil {
		t.Fatalf("second Ensure created=%v err=%v", again, err)
	}
	if _, err := db.GetUserByGamertag(ctx, "NAME ACCT1"); err != nil {
		t.Fatal("gamertag lookup is case-insensitive:", err)
	}
}

func TestEnsureCollisionsAndStatus(t *testing.T) {
	s, c, db := setup(t)
	ctx := context.Background()
	// coretest names accounts "name-<id>": both sanitize to the same prefix once truncated.
	long1, long2 := "abcdefghijklmnopq-1", "abcdefghijklmnopq-2"
	c.AddAccount(long1, pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	c.AddAccount(long2, pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	c.AddAccount("banned", pb.AccountStatus_ACCOUNT_STATUS_BANNED)
	for _, a := range []string{long1, long2, "banned"} {
		if _, err := s.Ensure(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	u1, _, _ := db.ActiveUserOf(ctx, long1)
	u2, ok2, _ := db.ActiveUserOf(ctx, long2)
	if !ok2 || u1.Gamertag == u2.Gamertag || len(u1.Gamertag) > 15 || len(u2.Gamertag) > 15 {
		t.Fatalf("collision handling: %q %q", u1.Gamertag, u2.Gamertag)
	}
	if _, ok, _ := db.ActiveUserOf(ctx, "banned"); ok {
		t.Fatal("banned accounts get no identity")
	}
}

func TestAdoptsExistingRealLinkAndKeepsXUIDAndGamertag(t *testing.T) {
	s, c, db := setup(t)
	ctx := context.Background()
	c.AddAccount("seed", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	id, _ := c.ReserveLink(ctx, "seed", "00095feff338cc25", "k")
	c.ActivateLink(ctx, id, "k2")
	c.SetLinkPublicCode(ctx, id, "xbtest2")
	if ok, err := s.Ensure(ctx, "seed"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	u, _, _ := db.ActiveUserOf(ctx, "seed")
	if u.XUID != "00095feff338cc25" || u.Gamertag != "xbtest2" {
		t.Fatalf("%+v", u)
	}
}

func TestReleaseRetiresAndFreesTheGamertag(t *testing.T) {
	s, c, db := setup(t)
	ctx := context.Background()
	c.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	s.Ensure(ctx, "acct1")
	if err := s.Release(ctx, "acct1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.ActiveUserOf(ctx, "acct1"); ok {
		t.Fatal("still active")
	}
	if _, err := db.GetUserByGamertag(ctx, "name acct1"); err == nil {
		t.Fatal("alias must be freed")
	}
	if _, err := c.GetActiveLinkByAccount(ctx, "acct1"); err == nil {
		t.Fatal("link must be unlinked")
	}
	// A later Ensure (failed enrolment) allocates the next generation, not the retired subject.
	if ok, err := s.Ensure(ctx, "acct1"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if u, _, _ := db.ActiveUserOf(ctx, "acct1"); u.XUID != XUID("acct1", 1) {
		t.Fatalf("re-ensure xuid %s", u.XUID)
	}
}

func TestDisplayNameChangeDoesNotRenameAfterCreation(t *testing.T) {
	s, c, db := setup(t)
	ctx := context.Background()
	c.Names = map[string]string{"a1": "Old Name"}
	c.AddAccount("a1", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	s.Ensure(ctx, "a1")
	c.Names["a1"] = "Brand New"
	s.Ensure(ctx, "a1")
	if u, _, _ := db.ActiveUserOf(ctx, "a1"); u.Gamertag != "Old Name" {
		t.Fatalf("gamertag followed the display name: %q", u.Gamertag)
	}
}
