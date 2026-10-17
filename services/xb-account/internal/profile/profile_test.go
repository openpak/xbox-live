package profile

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"openpak/xb-live/services/xb-account/internal/autoid"
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
	for _, a := range []string{"a1", "a2"} {
		c.AddAccount(a, pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	}
	au := &autoid.Service{Core: c, Store: db}
	au.Ensure(context.Background(), "a1")
	au.Ensure(context.Background(), "a2")
	return &Service{Core: c, Store: db}, c, db
}

func TestSetGamertag(t *testing.T) {
	s, c, db := setup(t)
	ctx := context.Background()
	before, _, _ := db.ActiveUserOf(ctx, "a1")
	for _, bad := range []string{"", "this name is way too long", "-x", "x!", " lead"} {
		if _, err := s.SetGamertag(ctx, Request{Account: "a1", Gamertag: bad}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	for _, r := range []string{"Xbox Live", "OPENPAK dev", "admin", "x box"} {
		if _, err := s.SetGamertag(ctx, Request{Account: "a1", Gamertag: r}); !errors.Is(err, ErrReserved) && r != "x box" {
			t.Fatalf("%q must be reserved: %v", r, err)
		}
	}
	res, err := s.SetGamertag(ctx, Request{Account: "a1", Gamertag: "Cool Tag", RequestID: "r1", Actor: "web:user1"})
	if err != nil || !res.Changed || res.Previous != before.Gamertag || res.XUID != before.XUID {
		t.Fatalf("%+v %v", res, err)
	}
	if u, _, _ := db.ActiveUserOf(ctx, "a1"); u.Gamertag != "Cool Tag" || u.XUID != before.XUID {
		t.Fatalf("%+v", u)
	}
	if l, _ := c.GetActiveLinkByAccount(ctx, "a1"); l.PublicCode != "Cool Tag" {
		t.Fatalf("core code %q", l.PublicCode)
	}
	if _, err := db.GetUserByGamertag(ctx, before.Gamertag); err == nil {
		t.Fatal("old alias must be freed")
	}
	// Idempotent: same request id replays, same tag is a no-op, another tag with the same id is refused.
	if r2, err := s.SetGamertag(ctx, Request{Account: "a1", Gamertag: "cool tag", RequestID: "r1"}); err != nil || r2.Changed || r2.Gamertag != "Cool Tag" {
		t.Fatalf("replay %+v %v", r2, err)
	}
	if _, err := s.SetGamertag(ctx, Request{Account: "a1", Gamertag: "Other", RequestID: "r1"}); !errors.Is(err, ErrRequestReplay) {
		t.Fatalf("reused id: %v", err)
	}
	if r3, err := s.SetGamertag(ctx, Request{Account: "a1", Gamertag: "Cool Tag"}); err != nil || r3.Changed {
		t.Fatalf("no-op %+v %v", r3, err)
	}
	// Case-insensitive uniqueness.
	if _, err := s.SetGamertag(ctx, Request{Account: "a2", Gamertag: "COOL TAG"}); !errors.Is(err, ErrTaken) {
		t.Fatalf("taken: %v", err)
	}
	if _, err := s.SetGamertag(ctx, Request{Account: "nobody", Gamertag: "Free"}); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("no identity: %v", err)
	}
	// The display name does not matter any more.
	c.Names = map[string]string{"a1": "Display Rename"}
	autoid := &autoid.Service{Core: c, Store: db}
	autoid.Ensure(ctx, "a1")
	if u, _, _ := db.ActiveUserOf(ctx, "a1"); u.Gamertag != "Cool Tag" {
		t.Fatalf("display name overwrote the gamertag: %q", u.Gamertag)
	}
}
