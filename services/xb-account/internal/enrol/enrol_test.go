// SPDX-License-Identifier: AGPL-3.0-only

package enrol

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcodes"
	"openpak/xb-live/internal/xbenrolapi"
	"openpak/xb-live/services/xb-account/internal/core"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
	"openpak/xb-live/services/xb-account/internal/coretest"
	"openpak/xb-live/services/xb-account/internal/store"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

const machine = "0000001cbe991a14"

var key = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

type env struct {
	core *coretest.Core
	db   *store.Store
	s    *Service
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
	v := &voucher.Service{Core: e.core, Store: db, Now: e.clock}
	e.s = &Service{Core: e.core, Store: db, Vouchers: v, Now: e.clock}
	return e
}

func (e *env) clock() time.Time        { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
func (e *env) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

func (e *env) enrol(t *testing.T, mach string) EnrolResult {
	t.Helper()
	r, err := e.s.Enrol(context.Background(), EnrolRequest{MachineID: mach, MachineKey: key})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	return r
}

func TestEnrolApproveActivatesDevice(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	r := e.enrol(t, machine)
	if len(r.PairingCode) != 8 || r.PollToken == "" {
		t.Fatalf("bad result %+v", r)
	}
	if st, _, err := e.s.Poll(ctx, r.PollToken); err != nil || st != xbenrolapi.StatusPending {
		t.Fatalf("poll %q %v", st, err)
	}
	// Pending grants nothing: the device is not admitted and has no key.
	if _, err := e.db.GetDevice(ctx, machine); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("pending enrolment created a device")
	}
	pv, err := e.s.Preview(ctx, "acct1", strings.ToLower(r.PairingCode))
	if err != nil || pv.MachineIDSuffix != "1a14" {
		t.Fatalf("preview %+v %v", pv, err)
	}
	if _, err := e.s.Approve(ctx, "acct1", xbcodes.FormatPairing(r.PairingCode)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if st, _, _ := e.s.Poll(ctx, r.PollToken); st != xbenrolapi.StatusApproved {
		t.Fatalf("poll after approve: %q", st)
	}
	d, err := e.db.GetDevice(ctx, machine)
	if err != nil || d.Status != xbaccountapi.StatusActive || d.CoreAccountID != "acct1" || d.Signup != store.SignupAwaitingGamertag || d.XUID == "" {
		t.Fatalf("device %+v %v", d, err)
	}
	l, err := e.core.GetActiveLinkByAccount(ctx, "acct1")
	if err != nil || l.SubjectID != d.XUID || l.LinkID != d.LinkID || l.PublicCode != "" {
		t.Fatalf("core link %+v %v", l, err)
	}
	if got, err := e.db.DeviceKey(ctx, machine); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("sealed machine key not recoverable: %v", err)
	}
	// Replay by the same account is idempotent; another account sees nothing.
	if a, err := e.s.Approve(ctx, "acct1", r.PairingCode); err != nil || !a.Replay {
		t.Fatalf("replay: %+v %v", a, err)
	}
	if _, err := e.s.Approve(ctx, "acct2", r.PairingCode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other account: %v", err)
	}
	if got := e.core.CountOps("ReserveLink"); got != 1 {
		t.Fatalf("ReserveLink called %d times", got)
	}
}

func TestEnrolNegatives(t *testing.T) {
	ctx := context.Background()
	t.Run("malformed input", func(t *testing.T) {
		e := setup(t)
		for _, r := range []EnrolRequest{
			{MachineID: "0009000000000001", MachineKey: key}, // an XUID, not a machine ID
			{MachineID: "nothex", MachineKey: key},
			{MachineID: machine, MachineKey: key[:15]},
			{MachineID: machine, MachineKey: make([]byte, 16)},
			{MachineID: machine, MachineKey: bytes.Repeat([]byte{0xff}, 16)},
			{MachineID: machine, MachineKey: key, ClientInfo: "bad\x00info"},
			{MachineID: machine, MachineKey: key, ClientInfo: strings.Repeat("a", 65)},
		} {
			if _, err := e.s.Enrol(ctx, r); !errors.Is(err, ErrInvalid) {
				t.Errorf("%+v: %v", r, err)
			}
		}
	})
	t.Run("expired", func(t *testing.T) {
		e := setup(t)
		r := e.enrol(t, machine)
		e.advance(11 * time.Minute)
		if st, _, _ := e.s.Poll(ctx, r.PollToken); st != xbenrolapi.StatusExpired {
			t.Fatalf("poll: %q", st)
		}
		if _, err := e.s.Approve(ctx, "acct1", r.PairingCode); !errors.Is(err, ErrNotFound) {
			t.Fatalf("approve expired: %v", err)
		}
		if _, err := e.db.GetDevice(ctx, machine); err == nil {
			t.Fatal("expired enrolment created a device")
		}
	})
	t.Run("wrong and malformed code, same answer", func(t *testing.T) {
		e := setup(t)
		e.enrol(t, machine)
		for _, c := range []string{"AAAAAAAA", "short", "", "ABCDEFG0"} {
			if _, err := e.s.Approve(ctx, "acct1", c); !errors.Is(err, ErrNotFound) {
				t.Errorf("%q: %v", c, err)
			}
		}
	})
	t.Run("guess limit per account and globally", func(t *testing.T) {
		e := setup(t)
		r := e.enrol(t, machine)
		for i := 0; i < 5; i++ {
			e.s.Approve(ctx, "acct1", "AAAAAAAA")
		}
		// Even the right code is refused while the account is over its budget.
		if _, err := e.s.Approve(ctx, "acct1", r.PairingCode); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("after 5 misses: %v", err)
		}
		e.advance(11 * time.Minute)
		if _, err := e.s.Approve(ctx, "acct1", r.PairingCode); !errors.Is(err, ErrNotFound) { // expired by now, but allowed to ask again
			t.Fatalf("after window: %v", err)
		}
		e2 := setup(t)
		for i := 0; i < 60; i++ {
			e2.s.Approve(ctx, "acct-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "AAAAAAAA")
		}
		if _, err := e2.s.Approve(ctx, "acct1", "AAAAAAAA"); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("global limit: %v", err)
		}
	})
	t.Run("already enrolled machine", func(t *testing.T) {
		e := setup(t)
		r := e.enrol(t, machine)
		if _, err := e.s.Approve(ctx, "acct1", r.PairingCode); err != nil {
			t.Fatal(err)
		}
		if _, err := e.s.Enrol(ctx, EnrolRequest{MachineID: machine, MachineKey: key}); !errors.Is(err, ErrMachineActive) {
			t.Fatalf("re-enrol active machine: %v", err)
		}
	})
	t.Run("machine becomes active while pending", func(t *testing.T) {
		e := setup(t)
		r1 := e.enrol(t, machine)
		// Another account completes an enrolment for the same machine ID first
		// (the second enrolment replaces the first pending one).
		r2 := e.enrol(t, machine)
		if _, err := e.s.Approve(ctx, "acct1", r1.PairingCode); !errors.Is(err, ErrNotFound) {
			t.Fatalf("replaced enrolment still approvable: %v", err)
		}
		if _, err := e.s.Approve(ctx, "acct2", r2.PairingCode); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("per machine rate limit", func(t *testing.T) {
		e := setup(t)
		var err error
		for i := 0; i < 7 && err == nil; i++ {
			_, err = e.s.Enrol(ctx, EnrolRequest{MachineID: machine, MachineKey: key})
		}
		if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("account already linked", func(t *testing.T) {
		e := setup(t)
		r := e.enrol(t, machine)
		if _, err := e.s.Approve(ctx, "acct1", r.PairingCode); err != nil {
			t.Fatal(err)
		}
		r2 := e.enrol(t, "0000001cbe991a15")
		if _, err := e.s.Approve(ctx, "acct1", r2.PairingCode); !errors.Is(err, ErrConflict) {
			t.Fatalf("second device for a linked account: %v", err)
		}
	})
	t.Run("ineligible account", func(t *testing.T) {
		e := setup(t)
		e.core.AddAccount("banned", pb.AccountStatus_ACCOUNT_STATUS_BANNED)
		r := e.enrol(t, machine)
		if _, err := e.s.Approve(ctx, "banned", r.PairingCode); !errors.Is(err, ErrAccount) {
			t.Fatalf("banned: %v", err)
		}
		if _, err := e.s.Approve(ctx, "nobody", r.PairingCode); !errors.Is(err, ErrAccount) {
			t.Fatalf("unknown: %v", err)
		}
		// The code is not consumed by a refusal.
		if _, err := e.s.Approve(ctx, "acct1", r.PairingCode); err != nil {
			t.Fatalf("approve after refusal: %v", err)
		}
	})
	t.Run("unknown poll token", func(t *testing.T) {
		e := setup(t)
		if _, _, err := e.s.Poll(ctx, "nope"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	})
}

func TestApproveResumesAndRollsBack(t *testing.T) {
	ctx := context.Background()
	t.Run("core down mid-flight, retry resumes without a second reserve", func(t *testing.T) {
		e := setup(t)
		r := e.enrol(t, machine)
		down := true
		e.core.Fail = func(op string) error {
			if down && op == "ActivateLink" {
				return core.ErrUnavailable
			}
			return nil
		}
		if _, err := e.s.Approve(ctx, "acct1", r.PairingCode); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("first: %v", err)
		}
		down = false
		if _, err := e.s.Approve(ctx, "acct1", r.PairingCode); err != nil {
			t.Fatalf("retry: %v", err)
		}
		if got := e.core.CountOps("ReserveLink"); got != 1 {
			t.Fatalf("reserve %d times", got)
		}
	})
	t.Run("a stuck approval is rolled back by Reap after expiry", func(t *testing.T) {
		e := setup(t)
		r := e.enrol(t, machine)
		e.core.Fail = func(op string) error {
			if op == "ActivateLink" {
				return core.ErrUnavailable
			}
			return nil
		}
		e.s.Approve(ctx, "acct1", r.PairingCode)
		e.core.Fail = nil
		e.advance(11 * time.Minute)
		if n, err := e.s.Reap(ctx); err != nil || n != 1 {
			t.Fatalf("reap %d %v", n, err)
		}
		if _, err := e.core.GetActiveLinkByAccount(ctx, "acct1"); err == nil {
			t.Fatal("core link survived the rollback")
		}
		if st, _, _ := e.s.Poll(ctx, r.PollToken); st != xbenrolapi.StatusExpired {
			t.Fatalf("poll after rollback: %q", st)
		}
	})
}

func approved(t *testing.T, e *env) {
	t.Helper()
	r := e.enrol(t, machine)
	if _, err := e.s.Approve(context.Background(), "acct1", r.PairingCode); err != nil {
		t.Fatal(err)
	}
}

func TestSignupConsumesSubscriptionCode(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	approved(t, e)
	if st, _ := e.s.AccountState(ctx, "acct1"); st.State != "device_linked" {
		t.Fatalf("state %+v", st)
	}
	iss, err := e.s.Vouchers.Issue(ctx, "acct1", machine)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(iss.Code, "-"); n != 4 || len(iss.Code) != 29 {
		t.Fatalf("format %q", iss.Code)
	}
	if err := e.s.Vouchers.Check(ctx, machine, strings.ToLower(strings.ReplaceAll(iss.Code, "-", " "))); err != nil {
		t.Fatalf("verify (case/separator insensitive): %v", err)
	}
	// verify does not consume
	if err := e.s.Vouchers.Check(ctx, machine, iss.Code); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	su, err := e.s.CompleteSignup(ctx, machine, iss.Code, "Player One")
	if err != nil || su.Gamertag != "Player One" {
		t.Fatalf("signup: %+v %v", su, err)
	}
	d, _ := e.db.GetDevice(ctx, machine)
	if d.Signup != store.SignupComplete || su.XUID != d.XUID {
		t.Fatalf("device after signup %+v", d)
	}
	if l, _ := e.core.GetLinkBySubject(ctx, su.XUID); l.PublicCode != "Player One" {
		t.Fatalf("core public code %q", l.PublicCode)
	}
	if u, err := e.db.GetUserByGamertag(ctx, "player one"); err != nil || u.XUID != su.XUID {
		t.Fatalf("alias: %+v %v", u, err)
	}
	if st, _ := e.s.AccountState(ctx, "acct1"); st.State != "user_linked" || st.Gamertag != "Player One" {
		t.Fatalf("state %+v", st)
	}
	// Replay with the same code and name is idempotent; the code is single use.
	if _, err := e.s.CompleteSignup(ctx, machine, iss.Code, "Player One"); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if _, err := e.s.CompleteSignup(ctx, machine, iss.Code, "Other Name"); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("second signup: %v", err)
	}
	if err := e.s.Vouchers.Check(ctx, machine, iss.Code); err == nil {
		t.Fatal("code still verifies after signup")
	}
}

func TestVoucherNegatives(t *testing.T) {
	ctx := context.Background()
	t.Run("expired, wrong machine, wrong account, revoked by newer code", func(t *testing.T) {
		e := setup(t)
		approved(t, e)
		old, _ := e.s.Vouchers.Issue(ctx, "acct1", "")
		cur, err := e.s.Vouchers.Issue(ctx, "acct1", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.s.CompleteSignup(ctx, machine, old.Code, "Player One"); !errors.Is(err, ErrVoucherBad) {
			t.Fatalf("revoked code: %v", err)
		}
		other, _ := e.s.Vouchers.Issue(ctx, "acct2", "")
		if _, err := e.s.CompleteSignup(ctx, machine, other.Code, "Player One"); !errors.Is(err, ErrVoucherBad) {
			t.Fatalf("another account's code: %v", err)
		}
		bound, _ := e.s.Vouchers.Issue(ctx, "acct1", "0000001cbe991a15")
		if _, err := e.s.CompleteSignup(ctx, machine, bound.Code, "Player One"); !errors.Is(err, ErrVoucherBad) {
			t.Fatalf("code bound to another machine: %v", err)
		}
		_ = cur
		again, _ := e.s.Vouchers.Issue(ctx, "acct1", machine)
		e.advance(31 * time.Minute)
		if _, err := e.s.CompleteSignup(ctx, machine, again.Code, "Player One"); !errors.Is(err, ErrVoucherBad) {
			t.Fatalf("expired code: %v", err)
		}
	})
	t.Run("malformed codes and per-machine failure budget", func(t *testing.T) {
		e := setup(t)
		approved(t, e)
		good, _ := e.s.Vouchers.Issue(ctx, "acct1", machine)
		var err error
		for i := 0; i < 12 && !errors.Is(err, ErrRateLimited); i++ {
			_, err = e.s.CompleteSignup(ctx, machine, strings.Repeat("A", 24), "Player One")
		}
		if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("no budget: %v", err)
		}
		if _, err := e.s.CompleteSignup(ctx, machine, good.Code, "Player One"); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("correct code accepted while limited: %v", err)
		}
	})
	t.Run("not enrolled / unlinked device", func(t *testing.T) {
		e := setup(t)
		c, _ := e.s.Vouchers.Issue(ctx, "acct1", "")
		if _, err := e.s.CompleteSignup(ctx, machine, c.Code, "Player One"); !errors.Is(err, ErrNoDevice) {
			t.Fatalf("never enrolled: %v", err)
		}
		approved(t, e)
		d, _ := e.db.GetDevice(ctx, machine)
		e.db.ApplyChange(ctx, store.Change{EventID: "e1", Version: 1, AccountID: "acct1", UnlinkXUID: d.XUID})
		if _, err := e.s.CompleteSignup(ctx, machine, c.Code, "Player One"); !errors.Is(err, ErrNoDevice) {
			t.Fatalf("unlinked: %v", err)
		}
	})
	t.Run("gamertag taken", func(t *testing.T) {
		e := setup(t)
		approved(t, e)
		e.core.AddAccount("acct3", pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
		if _, err := e.db.ReserveName(ctx, "0000001cbe991a99", "acct3", "Taken Name", time.Hour, false); err != nil {
			t.Fatal(err)
		}
		c, _ := e.s.Vouchers.Issue(ctx, "acct1", machine)
		if _, err := e.s.CompleteSignup(ctx, machine, c.Code, "taken name"); !errors.Is(err, ErrGamertagTaken) {
			t.Fatalf("got %v", err)
		}
		if _, err := e.s.CompleteSignup(ctx, machine, c.Code, "Free Name"); err != nil {
			t.Fatalf("code must survive a taken-name refusal: %v", err)
		}
	})
	t.Run("issue guards", func(t *testing.T) {
		e := setup(t)
		e.core.AddAccount("banned", pb.AccountStatus_ACCOUNT_STATUS_BANNED)
		if _, err := e.s.Vouchers.Issue(ctx, "banned", ""); !errors.Is(err, voucher.ErrAccount) {
			t.Fatalf("banned: %v", err)
		}
		if _, err := e.s.Vouchers.Issue(ctx, "acct1", "zz"); !errors.Is(err, voucher.ErrInvalid) {
			t.Fatalf("bad machine: %v", err)
		}
		approved(t, e)
		if _, err := e.s.Vouchers.Issue(ctx, "acct2", machine); !errors.Is(err, voucher.ErrDeviceBound) {
			t.Fatalf("machine of another account: %v", err)
		}
		var err error
		for i := 0; i < 6 && err == nil; i++ {
			_, err = e.s.Vouchers.Issue(ctx, "acct1", "")
		}
		if !errors.Is(err, voucher.ErrRateLimited) {
			t.Fatalf("issue rate limit: %v", err)
		}
	})
}

func TestRevocationCoversEnrolledDevices(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, typ string }{
		{"unlink before signup", "link_unlinked"},
		{"credential revoked", "credential_revoked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t)
			approved(t, e)
			d, _ := e.db.GetDevice(ctx, machine)
			c := store.Change{EventID: "ev1", Version: 1, AccountID: "acct1"}
			if tc.typ == "link_unlinked" {
				c.UnlinkXUID = d.XUID
			} else {
				c.SetAccount = &store.StatusChange{From: []xbaccountapi.Status{xbaccountapi.StatusActive}, To: xbaccountapi.StatusRevoked, Devices: true}
			}
			if err := e.db.ApplyChange(ctx, c); err != nil {
				t.Fatal(err)
			}
			if d, _ := e.db.GetDevice(ctx, machine); d.Status == xbaccountapi.StatusActive {
				t.Fatalf("device still active after %s", tc.typ)
			}
			// A revoked device can enrol again.
			if _, err := e.s.Enrol(ctx, EnrolRequest{MachineID: machine, MachineKey: key}); err != nil {
				t.Fatalf("re-enrol after revoke: %v", err)
			}
		})
	}
}
