// SPDX-License-Identifier: AGPL-3.0-only

// Package provision implements web-approved provisioning of a native Xbox
// identity. A signed-in web user (account core) approves a console: Begin
// mints a short-lived single-use token bound to that core account and a
// device-generated challenge. The console later calls Finalize with the token,
// the same challenge, the chosen gamertag and a device proof secret.
//
// Finalize is a resumable, idempotent transaction against core's Links
// (namespace "xbox"): mint XUID -> ReserveLink -> ActivateLink ->
// SetLinkPublicCode(gamertag) -> local commit. Every step persists before the
// next, core calls carry deterministic idempotency keys, and a retry with the
// same inputs resumes or returns the original result. A terminal failure
// (gamertag taken, second primary user, device bound elsewhere, expired) rolls
// the core link back with UnlinkLink and burns the token.
//
// A token plus challenge is an authorization to provision, not Kerberos proof.
package provision

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

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-account/internal/autoid"
	"openpak/xb-live/services/xb-account/internal/core"
	"openpak/xb-live/services/xb-account/internal/projection"
	"openpak/xb-live/services/xb-account/internal/store"
)

const (
	DefaultTTL = 10 * time.Minute
	MaxTTL     = 15 * time.Minute
)

var (
	ErrInvalid       = errors.New("provision: invalid request")
	ErrAccount       = errors.New("provision: account not eligible")
	ErrAlreadyLinked = errors.New("provision: account already has a primary Xbox user")
	ErrDeviceBound   = errors.New("provision: device bound to another account")
	ErrToken         = errors.New("provision: token invalid") // unknown, wrong challenge or machine: indistinguishable
	ErrExpired       = errors.New("provision: token expired")
	ErrUsed          = errors.New("provision: token already used with different parameters")
	ErrGamertagTaken = errors.New("provision: gamertag unavailable")
	ErrFailed        = errors.New("provision: provisioning failed and was rolled back")
	ErrUnavailable   = errors.New("provision: temporarily unavailable, retry with the same request")
)

type Provisioner struct {
	Core  core.API
	Store *store.Store
	TTL   time.Duration
	Now   func() time.Time

	locks sync.Map // token id -> *sync.Mutex
}

func (p *Provisioner) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Provisioner) lock(id string) func() {
	m, _ := p.locks.LoadOrStore(id, new(sync.Mutex))
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

type BeginRequest struct {
	CoreAccountID string
	MachineID     string // 16 lowercase hex
	Challenge     string // device-generated nonce, 16..128 printable ASCII chars
}

func validChallenge(c string) bool {
	if len(c) < 16 || len(c) > 128 {
		return false
	}
	for _, r := range c {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func tokenID(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Begin records an approval and returns the one-time token (shown once; only
// its hash is stored).
func (p *Provisioner) Begin(ctx context.Context, r BeginRequest) (token string, expires time.Time, err error) {
	if r.CoreAccountID == "" || !xbaccountapi.ValidMachineID(r.MachineID) || !validChallenge(r.Challenge) {
		return "", time.Time{}, ErrInvalid
	}
	acct, err := p.Core.GetAccount(ctx, r.CoreAccountID)
	if errors.Is(err, core.ErrNotFound) || err == nil && acct.Status != pb.AccountStatus_ACCOUNT_STATUS_ACTIVE {
		return "", time.Time{}, ErrAccount
	}
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	if l, err := p.Core.GetActiveLinkByAccount(ctx, r.CoreAccountID); err == nil && !projection.Is(l.SubjectID) && !p.autoIdentity(ctx, r.CoreAccountID) {
		return "", time.Time{}, ErrAlreadyLinked
	} else if err != nil && !errors.Is(err, core.ErrNotFound) {
		return "", time.Time{}, ErrUnavailable
	}
	if bound, err := p.Store.DeviceBoundElsewhere(ctx, r.MachineID, r.CoreAccountID); err != nil {
		return "", time.Time{}, ErrUnavailable
	} else if bound {
		return "", time.Time{}, ErrDeviceBound
	}
	ttl := p.TTL
	if ttl <= 0 || ttl > MaxTTL {
		ttl = DefaultTTL
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	expires = p.now().Add(ttl)
	rec := store.Provision{ID: tokenID(token), CoreAccountID: r.CoreAccountID, MachineID: r.MachineID,
		ChallengeHash: sha256.Sum256([]byte(r.Challenge)), Expires: expires}
	if err := p.Store.CreateProvision(ctx, rec); err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	return token, expires, nil
}

type FinalizeRequest struct {
	Token     string
	MachineID string
	Challenge string
	Gamertag  string
	Proof     []byte // the console's 16-byte machine key (xbcrypto.MachineKey); stored sealed + as a keyed MAC
}

type Result struct {
	XUID, Gamertag, MachineID, CoreAccountID string
}

func validGamertag(v string) bool {
	if len(v) < 1 || len(v) > 15 || v[0] == ' ' || v[len(v)-1] == ' ' {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ') {
			return false
		}
	}
	return true
}

func newXUID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// 0009 is the retail consumer XUID prefix; the remaining 48 bits are random.
	x := "0009" + hex.EncodeToString(b[:])
	if x == "0009000000000000" {
		return newXUID()
	}
	return x, nil
}

// Finalize performs or resumes the provisioning transaction.
func (p *Provisioner) Finalize(ctx context.Context, r FinalizeRequest) (Result, error) {
	if r.Token == "" || len(r.Token) > 128 || !xbaccountapi.ValidMachineID(r.MachineID) || !validChallenge(r.Challenge) ||
		!validGamertag(r.Gamertag) || len(r.Proof) != 16 {
		return Result{}, ErrInvalid
	}
	id := tokenID(r.Token)
	defer p.lock(id)()
	rec, err := p.Store.GetProvision(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Result{}, ErrToken
	}
	if err != nil {
		return Result{}, ErrUnavailable
	}
	ch := sha256.Sum256([]byte(r.Challenge))
	if subtle.ConstantTimeCompare(ch[:], rec.ChallengeHash[:]) != 1 || r.MachineID != rec.MachineID {
		return Result{}, ErrToken
	}
	mac := p.Store.ProofMAC(rec.MachineID, r.Proof)
	res := Result{rec.XUID, r.Gamertag, rec.MachineID, rec.CoreAccountID}

	switch rec.State {
	case store.ProvDone:
		if rec.Gamertag != r.Gamertag || subtle.ConstantTimeCompare(rec.ProofMAC, mac) != 1 {
			return Result{}, ErrUsed
		}
		return res, nil // idempotent replay
	case store.ProvFailed:
		return Result{}, ErrFailed
	case store.ProvRollback:
		return Result{}, p.rollback(ctx, rec)
	case store.ProvPending:
		if !p.now().Before(rec.Expires) {
			return Result{}, ErrExpired
		}
		xuid, err := newXUID()
		if err != nil {
			return Result{}, ErrUnavailable
		}
		sealed, err := p.Store.SealProof(rec.MachineID, r.Proof)
		if err != nil {
			return Result{}, ErrUnavailable
		}
		rec.State, rec.XUID, rec.Gamertag, rec.ProofMAC, rec.ProofSealed = store.ProvClaimed, xuid, r.Gamertag, mac, sealed
		if err := p.Store.SetProvision(ctx, rec); err != nil {
			return Result{}, ErrUnavailable
		}
	default: // in progress: inputs must match the claimed fingerprint
		if rec.Gamertag != r.Gamertag || subtle.ConstantTimeCompare(rec.ProofMAC, mac) != 1 {
			return Result{}, ErrUsed
		}
		if !p.now().Before(rec.Expires) {
			p.rollback(ctx, rec)
			return Result{}, ErrExpired
		}
	}
	res.XUID = rec.XUID
	if err := p.advance(ctx, &rec); err != nil {
		return Result{}, err
	}
	res.XUID = rec.XUID
	return res, nil
}

// fail records a terminal failure and rolls core back.
func (p *Provisioner) fail(ctx context.Context, rec *store.Provision, reason string, public error) error {
	rec.State, rec.FailReason = store.ProvRollback, reason
	if err := p.Store.SetProvision(ctx, *rec); err != nil {
		return ErrUnavailable
	}
	if err := p.rollback(ctx, *rec); errors.Is(err, ErrUnavailable) {
		return ErrUnavailable // rollback resumes on retry or Reap
	}
	return public
}

func (p *Provisioner) rollback(ctx context.Context, rec store.Provision) error {
	if rec.LinkID != "" {
		if err := p.Core.UnlinkLink(ctx, rec.LinkID, "xbprov:"+rec.ID+":rollback"); err != nil {
			return ErrUnavailable
		}
	}
	rec.State = store.ProvFailed
	if err := p.Store.SetProvision(ctx, rec); err != nil {
		return ErrUnavailable
	}
	return ErrFailed
}

func (p *Provisioner) advance(ctx context.Context, rec *store.Provision) error {
	idem := func(step string) string { return "xbprov:" + rec.ID + ":" + step }
	save := func(s store.ProvState) error {
		rec.State = s
		if p.Store.SetProvision(ctx, *rec) != nil {
			return ErrUnavailable
		}
		return nil
	}
	if rec.State == store.ProvClaimed {
		defer projection.Lock()()
		if (&autoid.Service{Core: p.Core, Store: p.Store}).Release(ctx, rec.CoreAccountID) != nil {
			return ErrUnavailable
		}
		if projection.Release(ctx, p.Core, rec.CoreAccountID) != nil {
			return ErrUnavailable
		}
		// One primary Xbox user per account, enforced in core before reserving.
		if l, err := p.Core.GetActiveLinkByAccount(ctx, rec.CoreAccountID); err == nil {
			if l.SubjectID != rec.XUID {
				return p.fail(ctx, rec, "account already linked", ErrAlreadyLinked)
			}
		} else if !errors.Is(err, core.ErrNotFound) {
			return ErrUnavailable
		}
		if _, err := p.Store.GetUserByGamertag(ctx, rec.Gamertag); err == nil {
			return p.fail(ctx, rec, "gamertag in use", ErrGamertagTaken)
		} else if !errors.Is(err, store.ErrNotFound) {
			return ErrUnavailable
		}
		for attempt := 0; ; attempt++ {
			linkID, err := p.Core.ReserveLink(ctx, rec.CoreAccountID, rec.XUID, idem("reserve:"+rec.XUID))
			if errors.Is(err, core.ErrConflict) && attempt < 5 { // XUID collision: mint another
				if rec.XUID, err = newXUID(); err != nil {
					return ErrUnavailable
				}
				continue
			}
			if errors.Is(err, core.ErrConflict) || errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrInvalid) {
				return p.fail(ctx, rec, "reserve rejected", ErrAlreadyLinked)
			}
			if err != nil {
				return ErrUnavailable
			}
			rec.LinkID = linkID
			break
		}
		if err := save(store.ProvReserved); err != nil {
			return err
		}
	}
	if rec.State == store.ProvReserved {
		err := p.Core.ActivateLink(ctx, rec.LinkID, idem("activate"))
		if errors.Is(err, core.ErrPrecondition) { // maybe a prior attempt already activated it
			if l, e := p.Core.GetLinkBySubject(ctx, rec.XUID); e == nil && l.State == pb.LinkState_LINK_STATE_ACTIVE && l.LinkID == rec.LinkID {
				err = nil
			}
		}
		switch {
		case errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrInvalid) || errors.Is(err, core.ErrConflict):
			return p.fail(ctx, rec, "activate rejected", ErrFailed)
		case err != nil:
			return ErrUnavailable
		}
		if err := save(store.ProvActivated); err != nil {
			return err
		}
	}
	if rec.State == store.ProvActivated {
		err := p.Core.SetLinkPublicCode(ctx, rec.LinkID, rec.Gamertag)
		switch {
		case errors.Is(err, core.ErrConflict):
			return p.fail(ctx, rec, "gamertag taken in core", ErrGamertagTaken)
		case errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrNotFound) || errors.Is(err, core.ErrInvalid):
			return p.fail(ctx, rec, "public code rejected", ErrFailed)
		case err != nil:
			return ErrUnavailable
		}
		if err := save(store.ProvCoded); err != nil {
			return err
		}
	}
	// ProvCoded: commit locally.
	if err := p.Store.CommitProvision(ctx, *rec); errors.Is(err, store.ErrConflict) {
		return p.fail(ctx, rec, "local invariant", ErrDeviceBound)
	} else if err != nil {
		return ErrUnavailable
	}
	return nil
}

// Reap rolls back provisions whose token expired mid-flight (or whose
// rollback could not reach core). Safe to run periodically; returns the
// number rolled back.
func (p *Provisioner) Reap(ctx context.Context) (int, error) {
	stale, err := p.Store.StaleProvisions(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, rec := range stale {
		unlock := p.lock(rec.ID)
		cur, err := p.Store.GetProvision(ctx, rec.ID)
		if err == nil && cur.State != store.ProvDone && cur.State != store.ProvFailed {
			if errors.Is(p.rollback(ctx, cur), ErrFailed) {
				n++
			}
		}
		unlock()
	}
	return n, nil
}

// autoIdentity reports whether the account's current Xbox identity is an
// automatic one (no credentials), which a real enrolment replaces.
func (p *Provisioner) autoIdentity(ctx context.Context, account string) bool {
	_, ok, err := p.Store.AutoIdentity(ctx, account)
	return err == nil && ok
}
