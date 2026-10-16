// SPDX-License-Identifier: AGPL-3.0-only

package resolver_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-account/internal/core"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
	"openpak/xb-live/services/xb-account/internal/coretest"
	"openpak/xb-live/services/xb-account/internal/provision"
	"openpak/xb-live/services/xb-account/internal/resolver"
	"openpak/xb-live/services/xb-account/internal/revoke"
	"openpak/xb-live/services/xb-account/internal/store"
)

const (
	machine   = "00aa00bb00cc00dd"
	challenge = "device-nonce-0123456789"
)

type world struct {
	core *coretest.Core
	db   *store.Store
	res  *resolver.Resolver
	proc *revoke.Processor
	xuid string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "x.db"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	c := coretest.New()
	c.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	p := &provision.Provisioner{Core: c, Store: db}
	tok, _, err := p.Begin(context.Background(), provision.BeginRequest{CoreAccountID: "acct1", MachineID: machine, Challenge: challenge})
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Finalize(context.Background(), provision.FinalizeRequest{Token: tok, MachineID: machine, Challenge: challenge, Gamertag: "Player One", Proof: bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return &world{c, db, &resolver.Resolver{Core: c, Store: db, PollInterval: 5 * time.Millisecond}, &revoke.Processor{Core: c, Store: db}, r.XUID}
}

func denial(err error) xbaccountapi.Status {
	var d *xbaccountapi.DeniedError
	if errors.As(err, &d) && errors.Is(err, xbaccountapi.ErrDenied) {
		return d.Principal.Status
	}
	return ""
}

func (w *world) user() error   { _, e := w.res.ResolveUser(context.Background(), w.xuid); return e }
func (w *world) device() error { _, e := w.res.ResolveDevice(context.Background(), machine); return e }

func TestResolveActive(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	u, err := w.res.ResolveUser(ctx, w.xuid)
	if err != nil || u.Kind != xbaccountapi.KindUser || u.CoreAccountID != "acct1" || u.Status != xbaccountapi.StatusActive {
		t.Fatalf("%+v %v", u, err)
	}
	d, err := w.res.ResolveDevice(ctx, machine)
	if err != nil || d.Kind != xbaccountapi.KindDevice || d.PrincipalID != machine || d.CoreAccountID != "acct1" {
		t.Fatalf("%+v %v", d, err)
	}
	// User and device ID spaces are distinct.
	if _, err := w.res.ResolveUser(ctx, machine); !errors.Is(err, xbaccountapi.ErrNotFound) {
		t.Fatalf("machine as user: %v", err)
	}
	if _, err := w.res.ResolveDevice(ctx, w.xuid); !errors.Is(err, xbaccountapi.ErrNotFound) {
		t.Fatalf("xuid as device: %v", err)
	}
	if _, err := w.res.ResolveUser(ctx, "nope"); !errors.Is(err, xbaccountapi.ErrInvalid) {
		t.Fatalf("invalid: %v", err)
	}
}

func TestLiveCoreDenialsBeforeAnyEventArrives(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.core.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_BANNED)
	if s := denial(w.user()); s != xbaccountapi.StatusBanned {
		t.Fatalf("user banned: %q", s)
	}
	if s := denial(w.device()); s != xbaccountapi.StatusBanned {
		t.Fatalf("device banned: %q", s)
	}
	w.core.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	l, _ := w.core.GetActiveLinkByAccount(ctx, "acct1")
	w.core.SetLinkState(l.LinkID, pb.LinkState_LINK_STATE_REVOKED)
	if s := denial(w.user()); s != xbaccountapi.StatusUnlinked {
		t.Fatalf("user unlinked: %q", s)
	}
	if s := denial(w.device()); s != xbaccountapi.StatusUnlinked {
		t.Fatalf("device unlinked: %q", s)
	}
	w.core.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_DELETION_PENDING)
	w.core.SetLinkState(l.LinkID, pb.LinkState_LINK_STATE_ACTIVE)
	if s := denial(w.user()); s != xbaccountapi.StatusDeleted {
		t.Fatalf("deletion pending: %q", s)
	}
}

func TestResolveGamertag(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	for _, tag := range []string{"Player One", "player one", "PLAYER ONE"} {
		p, err := w.res.ResolveGamertag(ctx, tag)
		if err != nil || p.PrincipalID != w.xuid || p.CoreAccountID != "acct1" {
			t.Fatalf("%q: %+v %v", tag, p, err)
		}
	}
	if _, err := w.res.ResolveGamertag(ctx, "Nobody"); !errors.Is(err, xbaccountapi.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := w.res.ResolveGamertag(ctx, "bad/tag"); !errors.Is(err, xbaccountapi.ErrInvalid) {
		t.Fatal(err)
	}
	w.core.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_BANNED)
	if denial(func() error { _, e := w.res.ResolveGamertag(ctx, "Player One"); return e }()) != xbaccountapi.StatusBanned {
		t.Fatal("banned gamertag admitted")
	}
	w.core.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	w.core.Emit("link_unlinked", "acct1", "xbox", w.xuid)
	process(t, w)
	if _, err := w.res.ResolveGamertag(ctx, "Player One"); !errors.Is(err, xbaccountapi.ErrNotFound) {
		t.Fatalf("unlinked alias must be released: %v", err)
	}
}

func TestCoreOutageDenies(t *testing.T) {
	w := newWorld(t)
	w.core.Fail = func(string) error { return core.ErrUnavailable }
	if err := w.user(); !errors.Is(err, xbaccountapi.ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if err := w.device(); !errors.Is(err, xbaccountapi.ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

func process(t *testing.T, w *world) int {
	t.Helper()
	n, err := w.proc.ProcessOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEventsBanUnbanAndRevocationStream(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.core.Emit("account_banned", "acct1", "", "")
	w.core.Emit("friend_requested", "acct1", "", "x") // irrelevant, still advances the cursor
	if n := process(t, w); n != 2 {
		t.Fatalf("processed %d", n)
	}
	u, _ := w.db.GetUser(ctx, w.xuid)
	d, _ := w.db.GetDevice(ctx, machine)
	if u.Status != xbaccountapi.StatusBanned || d.Status != xbaccountapi.StatusBanned {
		t.Fatalf("%v %v", u.Status, d.Status)
	}
	// Local status denies even if core would say active (stale core).
	w.core.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	if denial(w.user()) != xbaccountapi.StatusBanned {
		t.Fatal("banned user admitted")
	}
	revs, _ := w.res.Poll(ctx, 0, 10, 0)
	if len(revs) != 1 || revs[0].Scope != xbaccountapi.ScopeAccount || revs[0].Reason != xbaccountapi.StatusBanned || revs[0].CoreAccountID != "acct1" {
		t.Fatalf("%+v", revs)
	}
	w.core.Emit("account_unbanned", "acct1", "", "")
	process(t, w)
	if err := w.user(); err != nil {
		t.Fatalf("unban: %v", err)
	}
	if more, _ := w.res.Poll(ctx, revs[0].Seq, 10, 0); len(more) != 0 {
		t.Fatalf("unban is not a revocation: %+v", more)
	}
}

func TestUnlinkOnlyForXboxNamespaceAndRevokesDevices(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.core.Emit("link_unlinked", "acct1", "xbl", w.xuid) // wrong namespace: ignored
	w.core.Emit("link_unlinked", "acct1", "switch", "123")
	process(t, w)
	if u, _ := w.db.GetUser(ctx, w.xuid); u.Status != xbaccountapi.StatusActive {
		t.Fatal("foreign namespace unlinked an xbox user")
	}
	w.core.Emit("link_unlinked", "acct1", "xbox", w.xuid)
	process(t, w)
	u, _ := w.db.GetUser(ctx, w.xuid)
	d, _ := w.db.GetDevice(ctx, machine)
	if u.Status != xbaccountapi.StatusUnlinked || d.Status != xbaccountapi.StatusUnlinked {
		t.Fatalf("%v %v", u.Status, d.Status)
	}
	if _, err := w.db.GetUserByGamertag(ctx, "Player One"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("alias must be released on unlink")
	}
	revs, _ := w.res.Poll(ctx, 0, 10, 0)
	if len(revs) != 1 || revs[0].Scope != xbaccountapi.ScopeUser || revs[0].PrincipalID != w.xuid {
		t.Fatalf("%+v", revs)
	}
	// Unban must not resurrect an unlinked principal.
	w.core.Emit("account_banned", "acct1", "", "")
	w.core.Emit("account_unbanned", "acct1", "", "")
	process(t, w)
	if u, _ := w.db.GetUser(ctx, w.xuid); u.Status != xbaccountapi.StatusUnlinked {
		t.Fatalf("resurrected: %v", u.Status)
	}
}

func TestDeletionAndCredentialRevocation(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.core.Emit("credential_revoked", "acct1", "", "")
	process(t, w)
	if denial(w.device()) != xbaccountapi.StatusRevoked {
		t.Fatal("device not revoked")
	}
	if ok, _ := w.db.VerifyDeviceProof(ctx, machine, bytes.Repeat([]byte{9}, 32)); ok {
		t.Fatal("revoked device proof still verifies")
	}
	if err := w.user(); err != nil {
		t.Fatalf("user unaffected by device credential revocation: %v", err)
	}
	w.core.Emit("account_delete_started", "acct1", "", "")
	process(t, w)
	if denial(w.user()) != xbaccountapi.StatusDeleted || denial(w.device()) != xbaccountapi.StatusDeleted {
		t.Fatal("not deleted")
	}
	if u, _ := w.db.GetUser(ctx, w.xuid); u.Gamertag != "" {
		t.Fatal("gamertag retained after deletion")
	}
}

func TestProcessorIdempotentAndDurable(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	e := w.core.Emit("account_banned", "acct1", "", "")
	process(t, w)
	w.core.Redeliver(e) // at-least-once redelivery under a later version
	if n := process(t, w); n != 1 {
		t.Fatalf("processed %d", n)
	}
	if n := process(t, w); n != 0 {
		t.Fatalf("reprocessed %d", n)
	}
	revs, _ := w.res.Poll(ctx, 0, 10, 0)
	if len(revs) != 1 {
		t.Fatalf("duplicate revocations: %+v", revs)
	}
	// Cursor survives a restart.
	path := filepath.Join(t.TempDir(), "reopen.db")
	db1, _ := store.Open(path, bytes.Repeat([]byte{1}, 32))
	db1.ApplyChange(ctx, store.Change{EventID: "e1", Version: 41})
	db1.Close()
	db2, err := store.Open(path, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if v, _ := db2.Cursor(ctx); v != 41 {
		t.Fatalf("cursor %d", v)
	}
}

func TestProcessorStopsOnPollErrorWithoutAdvancing(t *testing.T) {
	w := newWorld(t)
	w.core.Emit("account_banned", "acct1", "", "")
	w.core.Fail = func(op string) error {
		if op == "PollEvents" {
			return core.ErrUnavailable
		}
		return nil
	}
	if _, err := w.proc.ProcessOnce(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if v, _ := w.db.Cursor(context.Background()); v != 0 {
		t.Fatalf("cursor advanced to %d", v)
	}
}

func TestPollWaitsForNewRevocation(t *testing.T) {
	w := newWorld(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(30 * time.Millisecond)
		w.core.Emit("account_banned", "acct1", "", "")
		w.proc.ProcessOnce(context.Background())
	}()
	revs, err := w.res.Poll(context.Background(), 0, 10, 3*time.Second)
	wg.Wait()
	if err != nil || len(revs) != 1 {
		t.Fatalf("%+v %v", revs, err)
	}
}

func TestConcurrentResolveAndProcess(t *testing.T) {
	w := newWorld(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				w.user()
				w.device()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.core.Emit("account_banned", "acct1", "", "")
		w.core.Emit("account_unbanned", "acct1", "", "")
		w.proc.ProcessOnce(context.Background())
	}()
	wg.Wait()
}
