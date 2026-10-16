// SPDX-License-Identifier: AGPL-3.0-only

package provision

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"openpak/xb-live/services/xb-account/internal/core"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
	"openpak/xb-live/services/xb-account/internal/coretest"
	"openpak/xb-live/services/xb-account/internal/store"
)

const (
	machine   = "00aa00bb00cc00dd"
	challenge = "device-nonce-0123456789"
)

var proof = bytes.Repeat([]byte{7}, 32)

type env struct {
	core *coretest.Core
	db   *store.Store
	p    *Provisioner
	now  time.Time
	mu   sync.Mutex
}

func setup(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "x.db"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{core: coretest.New(), db: db, now: time.Unix(1_800_000_000, 0)}
	e.core.AddAccount("acct1", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	e.core.AddAccount("acct2", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
	db.SetClock(e.clock)
	e.p = &Provisioner{Core: e.core, Store: db, Now: e.clock}
	return e
}

func (e *env) clock() time.Time        { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
func (e *env) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

func (e *env) begin(t *testing.T, acct, mach string) string {
	t.Helper()
	tok, _, err := e.p.Begin(context.Background(), BeginRequest{CoreAccountID: acct, MachineID: mach, Challenge: challenge})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	return tok
}

func fin(tok, tag string) FinalizeRequest {
	return FinalizeRequest{Token: tok, MachineID: machine, Challenge: challenge, Gamertag: tag, Proof: proof}
}

func TestHappyPathIsIdempotentAndUsesXboxNamespace(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tok := e.begin(t, "acct1", machine)
	res, err := e.p.Finalize(ctx, fin(tok, "Player One"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.XUID) != 16 || res.XUID[:4] != "0009" || res.CoreAccountID != "acct1" {
		t.Fatalf("result %+v", res)
	}
	l, err := e.core.GetActiveLinkByAccount(ctx, "acct1")
	if err != nil || l.SubjectID != res.XUID || l.PublicCode != "Player One" {
		t.Fatalf("core link %+v %v", l, err)
	}
	u, err := e.db.GetUser(ctx, res.XUID)
	if err != nil || u.Gamertag != "Player One" || u.Status != "active" {
		t.Fatalf("user %+v %v", u, err)
	}
	if ok, _ := e.db.VerifyDeviceProof(ctx, machine, proof); !ok {
		t.Fatal("device proof should verify")
	}
	if ok, _ := e.db.VerifyDeviceProof(ctx, machine, bytes.Repeat([]byte{8}, 32)); ok {
		t.Fatal("wrong proof verified")
	}
	// Retry: same result, no second core link, no extra reserve.
	res2, err := e.p.Finalize(ctx, fin(tok, "Player One"))
	if err != nil || res2 != res {
		t.Fatalf("replay %+v %v", res2, err)
	}
	if n := e.core.CountOps("ReserveLink"); n != 1 {
		t.Fatalf("reserve calls %d", n)
	}
	// Different parameters after use are rejected.
	if _, err := e.p.Finalize(ctx, fin(tok, "Other Tag")); !errors.Is(err, ErrUsed) {
		t.Fatalf("got %v", err)
	}
}

func TestTokenBinding(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tok := e.begin(t, "acct1", machine)
	bad := fin(tok, "P")
	bad.Challenge = "another-device-nonce-999"
	if _, err := e.p.Finalize(ctx, bad); !errors.Is(err, ErrToken) {
		t.Fatalf("wrong challenge: %v", err)
	}
	bad = fin(tok, "P")
	bad.MachineID = "1111111111111111"
	if _, err := e.p.Finalize(ctx, bad); !errors.Is(err, ErrToken) {
		t.Fatalf("wrong machine: %v", err)
	}
	if _, err := e.p.Finalize(ctx, fin("not-a-token", "P")); !errors.Is(err, ErrToken) {
		t.Fatalf("unknown token: %v", err)
	}
	if e.core.CountOps("ReserveLink") != 0 {
		t.Fatal("core touched on invalid token")
	}
	e.advance(DefaultTTL + time.Second)
	if _, err := e.p.Finalize(ctx, fin(tok, "P")); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for _, r := range []BeginRequest{{"", machine, challenge}, {"acct1", "xyz", challenge}, {"acct1", machine, "short"}} {
		if _, _, err := e.p.Begin(ctx, r); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", r, err)
		}
	}
	e.core.AddAccount("banned", pb.AccountStatus_ACCOUNT_STATUS_BANNED)
	if _, _, err := e.p.Begin(ctx, BeginRequest{CoreAccountID: "banned", MachineID: machine, Challenge: challenge}); !errors.Is(err, ErrAccount) {
		t.Fatalf("banned: %v", err)
	}
	tok := e.begin(t, "acct1", machine)
	for _, tag := range []string{"", " lead", "trail ", "way too long gamertag", "bad<>"} {
		if _, err := e.p.Finalize(ctx, fin(tok, tag)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%q: %v", tag, err)
		}
	}
	short := fin(tok, "P")
	short.Proof = []byte("tiny")
	if _, err := e.p.Finalize(ctx, short); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short proof: %v", err)
	}
}

func TestOnePrimaryUserPerAccount(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.p.Finalize(ctx, fin(e.begin(t, "acct1", machine), "One")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.p.Begin(ctx, BeginRequest{CoreAccountID: "acct1", MachineID: "2222222222222222", Challenge: challenge}); !errors.Is(err, ErrAlreadyLinked) {
		t.Fatalf("second begin: %v", err)
	}
}

func TestTwoTokensRaceForOneAccountOnlyOneWins(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	t1 := e.begin(t, "acct1", machine)
	t2 := e.begin(t, "acct1", "3333333333333333")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, tok := range []string{t1, t2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := fin(tok, []string{"Alpha", "Beta"}[i])
			if i == 1 {
				r.MachineID = "3333333333333333"
			}
			_, errs[i] = e.p.Finalize(ctx, r)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("want exactly one success, got %v", errs)
	}
	// The loser's core link, if any was reserved, must be gone.
	if l, err := e.core.GetActiveLinkByAccount(ctx, "acct1"); err != nil || l.PublicCode == "" {
		t.Fatalf("winner link %+v %v", l, err)
	}
}

func TestConcurrentFinalizeSameTokenOneUser(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tok := e.begin(t, "acct1", machine)
	var wg sync.WaitGroup
	res := make([]Result, 8)
	errs := make([]error, 8)
	for i := range res {
		wg.Add(1)
		go func() { defer wg.Done(); res[i], errs[i] = e.p.Finalize(ctx, fin(tok, "Same")) }()
	}
	wg.Wait()
	for i := range res {
		if errs[i] != nil || res[i] != res[0] {
			t.Fatalf("%d: %+v %v", i, res[i], errs[i])
		}
	}
	if n := e.core.CountOps("ReserveLink"); n != 1 {
		t.Fatalf("reserve %d", n)
	}
}

func TestGamertagTakenRollsBack(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.p.Finalize(ctx, fin(e.begin(t, "acct1", machine), "Taken")); err != nil {
		t.Fatal(err)
	}
	tok := e.begin(t, "acct2", "4444444444444444")
	r := fin(tok, "taken") // case-insensitive collision
	r.MachineID = "4444444444444444"
	if _, err := e.p.Finalize(ctx, r); !errors.Is(err, ErrGamertagTaken) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.core.GetActiveLinkByAccount(ctx, "acct2"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("acct2 must have no active link: %v", err)
	}
	if _, err := e.p.Finalize(ctx, r); !errors.Is(err, ErrFailed) {
		t.Fatalf("burned token: %v", err)
	}
}

func TestCoreOnlyCodeConflictRollsBack(t *testing.T) {
	// Local store knows nothing of the tag; core rejects the public code.
	e := setup(t)
	ctx := context.Background()
	e.core.Fail = nil
	id, _ := e.core.ReserveLink(ctx, "acct2", "0009ffffffffffff", "k")
	e.core.ActivateLink(ctx, id, "a")
	e.core.SetLinkPublicCode(ctx, id, "Elsewhere")
	tok := e.begin(t, "acct1", machine)
	if _, err := e.p.Finalize(ctx, fin(tok, "Elsewhere")); !errors.Is(err, ErrGamertagTaken) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.core.GetActiveLinkByAccount(ctx, "acct1"); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("link not rolled back")
	}
	if _, err := e.db.GetUserByGamertag(ctx, "Elsewhere"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("local user leaked")
	}
}

func TestTransientFailureResumesWithoutDuplicates(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tok := e.begin(t, "acct1", machine)
	fail := true
	e.core.Fail = func(op string) error {
		if op == "SetLinkPublicCode" && fail {
			return core.ErrUnavailable
		}
		return nil
	}
	if _, err := e.p.Finalize(ctx, fin(tok, "Resumer")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	// Different parameters cannot hijack a claimed provision.
	if _, err := e.p.Finalize(ctx, fin(tok, "Hijack")); !errors.Is(err, ErrUsed) {
		t.Fatalf("hijack: %v", err)
	}
	fail = false
	res, err := e.p.Finalize(ctx, fin(tok, "Resumer"))
	if err != nil {
		t.Fatal(err)
	}
	if e.core.CountOps("ReserveLink") != 1 || e.core.CountOps("ActivateLink") != 1 {
		t.Fatalf("steps repeated: reserve=%d activate=%d", e.core.CountOps("ReserveLink"), e.core.CountOps("ActivateLink"))
	}
	if u, err := e.db.GetUser(ctx, res.XUID); err != nil || u.Gamertag != "Resumer" {
		t.Fatalf("%+v %v", u, err)
	}
}

func TestDeviceBoundElsewhereRollsBack(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	t2 := e.begin(t, "acct2", machine) // both approvals exist before either finishes
	t1 := e.begin(t, "acct1", machine)
	if _, err := e.p.Finalize(ctx, fin(t1, "First")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.Finalize(ctx, fin(t2, "Second")); !errors.Is(err, ErrDeviceBound) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.core.GetActiveLinkByAccount(ctx, "acct2"); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("acct2 link must be rolled back")
	}
	if _, _, err := e.p.Begin(ctx, BeginRequest{CoreAccountID: "acct2", MachineID: machine, Challenge: challenge}); !errors.Is(err, ErrDeviceBound) {
		t.Fatalf("begin on bound device: %v", err)
	}
}

func TestReapRollsBackExpiredInFlight(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tok := e.begin(t, "acct1", machine)
	e.core.Fail = func(op string) error {
		if op == "SetLinkPublicCode" {
			return core.ErrUnavailable
		}
		return nil
	}
	if _, err := e.p.Finalize(ctx, fin(tok, "Stuck")); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	e.advance(DefaultTTL + time.Minute)
	n, err := e.p.Reap(ctx)
	if err != nil || n != 1 {
		t.Fatalf("reap %d %v", n, err)
	}
	if _, err := e.core.GetActiveLinkByAccount(ctx, "acct1"); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("expired provision left an active link")
	}
}

func TestRollbackSurvivesCoreOutage(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tok := e.begin(t, "acct1", machine)
	// Make the gamertag collide in core after activation, and make unlink fail once.
	id, _ := e.core.ReserveLink(ctx, "acct2", "0009eeeeeeeeeeee", "k")
	e.core.ActivateLink(ctx, id, "a")
	e.core.SetLinkPublicCode(ctx, id, "Clash")
	down := true
	e.core.Fail = func(op string) error {
		if op == "UnlinkLink" && down {
			return core.ErrUnavailable
		}
		return nil
	}
	if _, err := e.p.Finalize(ctx, fin(tok, "Clash")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	down = false
	if _, err := e.p.Finalize(ctx, fin(tok, "Clash")); !errors.Is(err, ErrFailed) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.core.GetActiveLinkByAccount(ctx, "acct1"); !errors.Is(err, core.ErrNotFound) {
		t.Fatal("link remained after rollback")
	}
}
