// SPDX-License-Identifier: AGPL-3.0-only

// Package enrol implements device-pairing enrolment of an original Xbox.
//
//  1. The console tool registers (machine ID, machine key) and gets a short
//     pairing code plus a poll token (Enrol). Nothing is trusted yet: the
//     enrolment is PENDING for ten minutes and anyone may create one for any
//     serial, so pending state grants nothing.
//  2. A signed-in, 2FA-verified web user enters the code (Preview, Approve).
//     Only the web side may do this; it names the core account.
//  3. Approve runs a resumable transaction against core Links (namespace
//     "xbox"): mint XUID -> ReserveLink -> ActivateLink -> commit the device
//     (sealed machine key) with signup pending. The XUID is reserved for the
//     account but has no gamertag and no users row yet.
//  4. The dashboard signup later calls CompleteSignup (createowneracct side)
//     with a subscription code, which publishes the gamertag as the link's
//     public code and creates the user.
//
// A device whose signup is pending is admitted by ResolveDevice (active
// device, active core link, active account), so MACS works and the dashboard
// can reach service 5. See docs/xbox/enrolment-contract.md for the state
// machine.
package enrol

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	pb "openpak/xb-live/services/xb-account/internal/corepb"

	"openpak/xb-live/internal/ratelimit"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcodes"
	"openpak/xb-live/internal/xbenrolapi"
	"openpak/xb-live/services/xb-account/internal/autoid"
	"openpak/xb-live/services/xb-account/internal/core"
	"openpak/xb-live/services/xb-account/internal/projection"
	"openpak/xb-live/services/xb-account/internal/store"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

const (
	DefaultTTL = 10 * time.Minute
	MaxTTL     = 15 * time.Minute
	// MaxPending bounds live pending enrolments (code space and disk).
	MaxPending = 5000
	// Keep is how long finished enrolments stay readable by the console.
	Keep = time.Hour
)

var (
	ErrInvalid       = errors.New("enrol: invalid request")
	ErrMachineActive = errors.New("enrol: machine already enrolled")
	ErrRateLimited   = errors.New("enrol: rate limited")
	ErrBusy          = errors.New("enrol: too many pending enrolments")
	ErrNotFound      = errors.New("enrol: not found") // unknown token/code, expired, used by another account
	ErrAccount       = errors.New("enrol: account not eligible")
	ErrConflict      = errors.New("enrol: account already linked or device bound elsewhere")
	ErrFailed        = errors.New("enrol: approval failed and was rolled back")
	ErrUnavailable   = errors.New("enrol: temporarily unavailable, retry with the same request")

	// Signup errors.
	ErrNoDevice      = errors.New("enrol: device not awaiting signup")
	ErrGamertagTaken = errors.New("enrol: gamertag unavailable")
	ErrVoucherBad    = voucher.ErrBad
	ErrVoucherUsed   = voucher.ErrUsed
)

type Service struct {
	Core     core.API
	Store    *store.Store
	Vouchers *voucher.Service
	TTL      time.Duration
	Now      func() time.Time

	locks sync.Map // enrolment id / machine id -> *sync.Mutex

	once       sync.Once
	perMachine *ratelimit.Window // enrol attempts per machine
	badCode    *ratelimit.Window // failed code lookups per approving account
	badAll     *ratelimit.Window // failed code lookups, everyone (distributed guessing)
}

func (s *Service) init() {
	s.once.Do(func() {
		s.perMachine = ratelimit.New(6, 10*time.Minute)
		s.badCode = ratelimit.New(5, 10*time.Minute)
		s.badAll = ratelimit.New(60, time.Minute)
		for _, w := range []*ratelimit.Window{s.perMachine, s.badCode, s.badAll} {
			w.Now = s.Now
		}
	})
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) lock(id string) func() {
	m, _ := s.locks.LoadOrStore(id, new(sync.Mutex))
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (s *Service) codeHash(canonical string) []byte { return s.Store.CodeHash("pairing", canonical) }

func pollHash(token string) []byte {
	h := sha256.Sum256([]byte("xb-poll\x00" + token))
	return h[:]
}

func randID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type EnrolRequest struct {
	MachineID  string
	MachineKey []byte
	ClientInfo string
}

type EnrolResult struct {
	PairingCode string
	PollToken   string
	Expires     time.Time
}

// Enrol registers a pending enrolment. The machine key is stored sealed and
// is never logged or returned.
func (s *Service) Enrol(ctx context.Context, r EnrolRequest) (EnrolResult, error) {
	s.init()
	info, okInfo := xbenrolapi.CleanClientInfo(r.ClientInfo)
	if !xbaccountapi.ValidMachineID(r.MachineID) || len(r.MachineKey) != 16 || !okInfo {
		return EnrolResult{}, ErrInvalid
	}
	if _, ok := xbenrolapi.ParseMachineKey(hex.EncodeToString(r.MachineKey)); !ok {
		return EnrolResult{}, ErrInvalid
	}
	if !s.perMachine.Allow(r.MachineID) {
		return EnrolResult{}, ErrRateLimited
	}
	sealed, err := s.Store.SealProof(r.MachineID, r.MachineKey)
	if err != nil {
		return EnrolResult{}, ErrUnavailable
	}
	ttl := s.TTL
	if ttl <= 0 || ttl > MaxTTL {
		ttl = DefaultTTL
	}
	exp := s.now().Add(ttl)
	for try := 0; try < 5; try++ {
		code, err := xbcodes.NewPairing()
		raw := make([]byte, 32)
		if err == nil {
			_, err = rand.Read(raw)
		}
		id, err2 := randID()
		if err != nil || err2 != nil {
			return EnrolResult{}, ErrUnavailable
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		e := store.Enrolment{ID: id, CodeHash: s.codeHash(code), PollHash: pollHash(token), MachineID: r.MachineID, ClientInfo: info,
			ProofMAC: s.Store.ProofMAC(r.MachineID, r.MachineKey), ProofSealed: sealed, Expires: exp}
		switch err := s.Store.CreateEnrolment(ctx, e, MaxPending); {
		case err == nil:
			return EnrolResult{PairingCode: code, PollToken: token, Expires: exp}, nil
		case errors.Is(err, store.ErrMachineActive):
			return EnrolResult{}, ErrMachineActive
		case errors.Is(err, store.ErrBusy):
			return EnrolResult{}, ErrBusy
		case errors.Is(err, store.ErrConflict):
			continue
		default:
			return EnrolResult{}, ErrUnavailable
		}
	}
	return EnrolResult{}, ErrUnavailable
}

// Poll reports the enrolment's status to the console that holds the token.
func (s *Service) Poll(ctx context.Context, token string) (status string, expires time.Time, err error) {
	if token == "" || len(token) > xbenrolapi.MaxTokenLen {
		return "", time.Time{}, ErrInvalid
	}
	e, err := s.Store.EnrolmentByPoll(ctx, pollHash(token))
	if errors.Is(err, store.ErrNotFound) {
		return "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	switch {
	case e.State == store.EnrolApproved:
		return xbenrolapi.StatusApproved, e.Expires, nil
	case e.State == store.EnrolFailed || e.State == store.EnrolRollback, !s.now().Before(e.Expires) && e.State == store.EnrolPending:
		return xbenrolapi.StatusExpired, e.Expires, nil
	}
	return xbenrolapi.StatusPending, e.Expires, nil // pending or being approved
}

// lookup finds the enrolment for a typed code, applying the guess limits.
// Every miss (unknown, expired, taken by another account, malformed) is
// ErrNotFound; misses count against the account and a global budget.
func (s *Service) lookup(ctx context.Context, account, typed string) (store.Enrolment, error) {
	s.init()
	if account == "" || len(account) > 128 {
		return store.Enrolment{}, ErrInvalid
	}
	if s.badCode.Blocked(account) || s.badAll.Blocked("all") {
		return store.Enrolment{}, ErrRateLimited
	}
	miss := func() (store.Enrolment, error) {
		s.badCode.Hit(account)
		s.badAll.Hit("all")
		return store.Enrolment{}, ErrNotFound
	}
	code, ok := xbcodes.NormalizePairing(typed)
	if !ok {
		return miss()
	}
	e, err := s.Store.EnrolmentByCode(ctx, s.codeHash(code))
	if errors.Is(err, store.ErrNotFound) {
		return miss()
	}
	if err != nil {
		return store.Enrolment{}, ErrUnavailable
	}
	if subtle.ConstantTimeCompare(e.CodeHash, s.codeHash(code)) != 1 {
		return miss()
	}
	if e.State == store.EnrolPending && !s.now().Before(e.Expires) || e.State == store.EnrolFailed || e.State == store.EnrolRollback {
		return miss()
	}
	if e.State != store.EnrolPending && e.CoreAccountID != account { // claimed by someone else
		return miss()
	}
	return e, nil
}

type Preview struct {
	MachineIDSuffix string // last four hex digits of the machine ID
	ClientInfo      string
	Expires         time.Time
	Approved        bool
}

// Preview shows what a code refers to so the approver can confirm it matches
// the console in front of them. It reveals no key and no full machine ID.
func (s *Service) Preview(ctx context.Context, account, typed string) (Preview, error) {
	e, err := s.lookup(ctx, account, typed)
	if err != nil {
		return Preview{}, err
	}
	return Preview{MachineIDSuffix: e.MachineID[12:], ClientInfo: e.ClientInfo, Expires: e.Expires, Approved: e.State == store.EnrolApproved}, nil
}

type Approval struct {
	MachineIDSuffix string
	Replay          bool
}

func newXUID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	x := "0009" + hex.EncodeToString(b[:])
	if x == "0009000000000000" {
		return newXUID()
	}
	return x, nil
}

// Approve binds a pending enrolment to a core account and activates its
// device. The caller (xb-provisioner, the website) must already have
// authenticated the user with 2FA; this service only trusts that identity.
// Repeating the same approval returns the original result.
func (s *Service) Approve(ctx context.Context, account, typed string) (Approval, error) {
	e, err := s.lookup(ctx, account, typed)
	if err != nil {
		return Approval{}, err
	}
	defer s.lock(e.ID)()
	if e, err = s.Store.GetEnrolment(ctx, e.ID); err != nil { // re-read under the lock
		return Approval{}, ErrNotFound
	}
	suffix := e.MachineID[12:]
	if e.State == store.EnrolApproved {
		if e.CoreAccountID != account {
			return Approval{}, ErrNotFound
		}
		return Approval{suffix, true}, nil
	}
	if e.State != store.EnrolPending && e.CoreAccountID != account {
		return Approval{}, ErrNotFound
	}
	if !s.now().Before(e.Expires) {
		if e.State != store.EnrolPending {
			s.rollback(ctx, e)
		}
		return Approval{}, ErrNotFound
	}
	if e.State == store.EnrolPending {
		a, err := s.Core.GetAccount(ctx, account)
		if errors.Is(err, core.ErrNotFound) || err == nil && a.Status != pb.AccountStatus_ACCOUNT_STATUS_ACTIVE {
			return Approval{}, ErrAccount
		}
		if err != nil {
			return Approval{}, ErrUnavailable
		}
		if l, err := s.Core.GetActiveLinkByAccount(ctx, account); err == nil && !projection.Is(l.SubjectID) && !s.autoIdentity(ctx, account) {
			return Approval{}, ErrConflict
		} else if err != nil && !errors.Is(err, core.ErrNotFound) {
			return Approval{}, ErrUnavailable
		}
		if d, err := s.Store.GetDevice(ctx, e.MachineID); err == nil && (d.Status == xbaccountapi.StatusActive || d.Status == xbaccountapi.StatusBanned) {
			return Approval{}, ErrConflict
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return Approval{}, ErrUnavailable
		}
		xuid, err := newXUID()
		if err != nil {
			return Approval{}, ErrUnavailable
		}
		e.State, e.CoreAccountID, e.XUID = store.EnrolApproving, account, xuid
		if err := s.Store.SetEnrolment(ctx, e); err != nil {
			return Approval{}, ErrUnavailable
		}
	}
	if e.State == store.EnrolRollback {
		return Approval{}, s.rollback(ctx, e)
	}
	if err := s.advance(ctx, &e); err != nil {
		return Approval{}, err
	}
	return Approval{suffix, false}, nil
}

func (s *Service) fail(ctx context.Context, e *store.Enrolment, reason string, public error) error {
	e.State, e.FailReason = store.EnrolRollback, reason
	if err := s.Store.SetEnrolment(ctx, *e); err != nil {
		return ErrUnavailable
	}
	if err := s.rollback(ctx, *e); errors.Is(err, ErrUnavailable) {
		return ErrUnavailable
	}
	return public
}

func (s *Service) rollback(ctx context.Context, e store.Enrolment) error {
	if e.LinkID != "" {
		if err := s.Core.UnlinkLink(ctx, e.LinkID, "xbenrol:"+e.ID+":rollback"); err != nil {
			return ErrUnavailable
		}
	}
	e.State = store.EnrolFailed
	if err := s.Store.SetEnrolment(ctx, e); err != nil {
		return ErrUnavailable
	}
	return ErrFailed
}

func (s *Service) advance(ctx context.Context, e *store.Enrolment) error {
	idem := func(step string) string { return "xbenrol:" + e.ID + ":" + step }
	save := func(st store.EnrolState) error {
		e.State = st
		if s.Store.SetEnrolment(ctx, *e) != nil {
			return ErrUnavailable
		}
		return nil
	}
	if e.State == store.EnrolApproving {
		// The console-less projection link yields to the real one; the gate keeps
		// the reconciler from re-creating it before we reserve.
		defer projection.Lock()()
		if (&autoid.Service{Core: s.Core, Store: s.Store}).Release(ctx, e.CoreAccountID) != nil {
			return ErrUnavailable
		}
		if projection.Release(ctx, s.Core, e.CoreAccountID) != nil {
			return ErrUnavailable
		}
		if l, err := s.Core.GetActiveLinkByAccount(ctx, e.CoreAccountID); err == nil {
			if l.SubjectID != e.XUID {
				return s.fail(ctx, e, "account already linked", ErrConflict)
			}
		} else if !errors.Is(err, core.ErrNotFound) {
			return ErrUnavailable
		}
		for attempt := 0; ; attempt++ {
			linkID, err := s.Core.ReserveLink(ctx, e.CoreAccountID, e.XUID, idem("reserve:"+e.XUID))
			if errors.Is(err, core.ErrConflict) && attempt < 5 { // XUID collision: mint another
				if e.XUID, err = newXUID(); err != nil {
					return ErrUnavailable
				}
				continue
			}
			if errors.Is(err, core.ErrConflict) || errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrInvalid) {
				return s.fail(ctx, e, "reserve rejected", ErrConflict)
			}
			if err != nil {
				return ErrUnavailable
			}
			e.LinkID = linkID
			break
		}
		if err := save(store.EnrolReserved); err != nil {
			return err
		}
	}
	if e.State == store.EnrolReserved {
		err := s.Core.ActivateLink(ctx, e.LinkID, idem("activate"))
		if errors.Is(err, core.ErrPrecondition) { // a prior attempt may already have activated it
			if l, e2 := s.Core.GetLinkBySubject(ctx, e.XUID); e2 == nil && l.State == pb.LinkState_LINK_STATE_ACTIVE && l.LinkID == e.LinkID {
				err = nil
			}
		}
		switch {
		case errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrInvalid) || errors.Is(err, core.ErrConflict):
			return s.fail(ctx, e, "activate rejected", ErrFailed)
		case err != nil:
			return ErrUnavailable
		}
		if err := save(store.EnrolActivated); err != nil {
			return err
		}
	}
	// EnrolActivated: commit the device locally.
	if err := s.Store.CommitEnrolment(ctx, *e); errors.Is(err, store.ErrConflict) {
		return s.fail(ctx, e, "local invariant", ErrConflict)
	} else if err != nil {
		return ErrUnavailable
	}
	e.State = store.EnrolApproved
	return nil
}

// Reap rolls back approvals whose time ran out mid-flight and purges old rows.
func (s *Service) Reap(ctx context.Context) (int, error) {
	stale, err := s.Store.StaleEnrolments(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, rec := range stale {
		unlock := s.lock(rec.ID)
		cur, err := s.Store.GetEnrolment(ctx, rec.ID)
		if err == nil && cur.State != store.EnrolApproved && cur.State != store.EnrolFailed {
			if errors.Is(s.rollback(ctx, cur), ErrFailed) {
				n++
			}
		}
		unlock()
	}
	return n, s.Store.PurgeEnrolments(ctx, Keep)
}

// AccountState is the website's view of an account's Xbox link.
type AccountState struct {
	State    string // none, device_linked, user_linked
	Gamertag string
	Devices  []DeviceState
}

type DeviceState struct {
	MachineIDSuffix string
	Status          xbaccountapi.Status
	Signup          string
}

func (s *Service) AccountState(ctx context.Context, account string) (AccountState, error) {
	if account == "" || len(account) > 128 {
		return AccountState{}, ErrInvalid
	}
	ax, err := s.Store.AccountXbox(ctx, account)
	if err != nil {
		return AccountState{}, ErrUnavailable
	}
	st := AccountState{State: "none"}
	for _, d := range ax.Devices {
		st.Devices = append(st.Devices, DeviceState{d.MachineID[12:], d.Status, d.Signup})
		if d.Status == xbaccountapi.StatusActive && d.Signup == store.SignupAwaitingGamertag {
			st.State = "device_linked"
		}
	}
	if ax.User != nil {
		st.State, st.Gamertag = "user_linked", ax.User.Gamertag
	}
	return st, nil
}

type Signup struct{ XUID, Gamertag, CoreAccountID string }

// CompleteSignup is the createowneracct side: the dashboard names a gamertag
// and presents a subscription code for the (already enrolled) device. It
// consumes the code and creates the user. Idempotent for the same device,
// code and gamertag. The account is always the device's own.
func (s *Service) CompleteSignup(ctx context.Context, machineID, typedCode, gamertag string) (Signup, error) {
	s.init()
	if !xbaccountapi.ValidMachineID(machineID) || !xbaccountapi.ValidGamertag(gamertag) {
		return Signup{}, ErrInvalid
	}
	if s.Vouchers.Limited(machineID) {
		return Signup{}, ErrRateLimited
	}
	code, ok := xbcodes.NormalizeVoucher(typedCode)
	if !ok {
		s.Vouchers.Fail(machineID)
		return Signup{}, ErrVoucherBad
	}
	hash := s.Vouchers.Hash(code)
	defer s.lock("signup:" + machineID)()
	d, err := s.Store.GetDevice(ctx, machineID)
	if errors.Is(err, store.ErrNotFound) {
		return Signup{}, ErrNoDevice
	}
	if err != nil {
		return Signup{}, ErrUnavailable
	}
	if d.Status != xbaccountapi.StatusActive {
		return Signup{}, ErrNoDevice
	}
	if d.Signup == store.SignupComplete { // replay of a finished signup?
		u, err := s.Store.GetUser(ctx, d.XUID)
		used, err2 := s.Store.VoucherConsumedBy(ctx, hash, machineID)
		if err == nil && err2 == nil && used && u.Gamertag == gamertag {
			return Signup{u.XUID, u.Gamertag, u.CoreAccountID}, nil
		}
		return Signup{}, ErrNoDevice
	}
	if d.Signup != store.SignupAwaitingGamertag || d.XUID == "" || d.LinkID == "" {
		return Signup{}, ErrNoDevice
	}
	if err := s.Store.CheckVoucher(ctx, hash, d.CoreAccountID, machineID); err != nil {
		switch {
		case errors.Is(err, store.ErrVoucherUsed):
			s.Vouchers.Fail(machineID)
			return Signup{}, ErrVoucherUsed
		case errors.Is(err, store.ErrVoucherInvalid):
			s.Vouchers.Fail(machineID)
			return Signup{}, ErrVoucherBad
		}
		return Signup{}, ErrUnavailable
	}
	if free, err := s.Store.NameAvailable(ctx, gamertag, d.CoreAccountID); err != nil {
		return Signup{}, ErrUnavailable
	} else if !free {
		return Signup{}, ErrGamertagTaken
	}
	// Publish the gamertag on the core link (idempotent for the same value).
	switch err := s.Core.SetLinkPublicCode(ctx, d.LinkID, gamertag); {
	case errors.Is(err, core.ErrConflict):
		return Signup{}, ErrGamertagTaken
	case errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrInvalid):
		return Signup{}, ErrNoDevice // the link is gone; revocation will follow
	case err != nil:
		return Signup{}, ErrUnavailable
	}
	u, err := s.Store.CommitSignup(ctx, machineID, hash, gamertag)
	switch {
	case err == nil:
		return Signup{u.XUID, u.Gamertag, u.CoreAccountID}, nil
	case errors.Is(err, store.ErrVoucherUsed):
		return Signup{}, ErrVoucherUsed
	case errors.Is(err, store.ErrVoucherInvalid):
		return Signup{}, ErrVoucherBad
	case errors.Is(err, store.ErrConflict):
		return Signup{}, ErrGamertagTaken
	case errors.Is(err, store.ErrNotFound):
		return Signup{}, ErrNoDevice
	}
	return Signup{}, ErrUnavailable
}

// autoIdentity reports whether the account's Xbox identity is an automatic one
// (no credentials); the real enrolment retires and replaces it.
func (s *Service) autoIdentity(ctx context.Context, account string) bool {
	_, ok, err := s.Store.AutoIdentity(ctx, account)
	return err == nil && ok
}
