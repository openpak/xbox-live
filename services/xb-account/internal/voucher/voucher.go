// SPDX-License-Identifier: AGPL-3.0-only

// Package voucher issues and verifies subscription codes: 25 characters
// (5x5, unambiguous uppercase alphanumerics, case-insensitive), single use,
// short-lived, bound to a core account and optionally to a machine ID. Codes
// are stored only as keyed hashes. Consuming happens inside the signup
// transaction (enrol.CompleteSignup, the createowneracct side); Check is the
// non-consuming verifyvoucher side.
package voucher

import (
	"context"
	"errors"
	"time"

	pb "openpak/xb-live/services/xb-account/internal/corepb"

	"openpak/xb-live/internal/ratelimit"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcodes"
	"openpak/xb-live/services/xb-account/internal/core"
	"openpak/xb-live/services/xb-account/internal/store"
)

const (
	DefaultTTL = 30 * time.Minute
	MaxTTL     = 60 * time.Minute
	hashLabel  = "voucher"
)

var (
	ErrInvalid     = errors.New("voucher: invalid request")
	ErrAccount     = errors.New("voucher: account not eligible")
	ErrDeviceBound = errors.New("voucher: machine bound to another account")
	ErrRateLimited = errors.New("voucher: rate limited")
	ErrBad         = errors.New("voucher: code invalid") // unknown, expired, revoked, wrong account or machine
	ErrUsed        = errors.New("voucher: code already used")
	ErrUnavailable = errors.New("voucher: temporarily unavailable")
)

type Service struct {
	Core  core.API
	Store *store.Store
	TTL   time.Duration
	Now   func() time.Time

	issue    *ratelimit.Window // per account
	failures *ratelimit.Window // per machine
}

func (s *Service) init() {
	if s.issue == nil {
		s.issue = ratelimit.New(5, 10*time.Minute)
		s.failures = ratelimit.New(10, 10*time.Minute)
		if s.Now != nil {
			s.issue.Now, s.failures.Now = s.Now, s.Now
		}
	}
}

// Hash is the storage key of a typed code (already normalised or not).
func (s *Service) Hash(canonical string) []byte { return s.Store.CodeHash(hashLabel, canonical) }

type Issued struct {
	Code    string // grouped for display: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
	Expires time.Time
}

// Issue creates a code for an active account. machineID may be empty. A newer
// code revokes the account's earlier unused ones.
func (s *Service) Issue(ctx context.Context, account, machineID string) (Issued, error) {
	s.init()
	if account == "" || len(account) > 128 || machineID != "" && !xbaccountapi.ValidMachineID(machineID) {
		return Issued{}, ErrInvalid
	}
	if !s.issue.Allow(account) {
		return Issued{}, ErrRateLimited
	}
	a, err := s.Core.GetAccount(ctx, account)
	if errors.Is(err, core.ErrNotFound) || err == nil && a.Status != pb.AccountStatus_ACCOUNT_STATUS_ACTIVE {
		return Issued{}, ErrAccount
	}
	if err != nil {
		return Issued{}, ErrUnavailable
	}
	if machineID != "" {
		if bound, err := s.Store.DeviceBoundElsewhere(ctx, machineID, account); err != nil {
			return Issued{}, ErrUnavailable
		} else if bound {
			return Issued{}, ErrDeviceBound
		}
	}
	ttl := s.TTL
	if ttl <= 0 || ttl > MaxTTL {
		ttl = DefaultTTL
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	for try := 0; try < 3; try++ {
		code, err := xbcodes.NewVoucher()
		if err != nil {
			return Issued{}, ErrUnavailable
		}
		exp := now.Add(ttl)
		err = s.Store.CreateVoucher(ctx, store.Voucher{Hash: s.Hash(code), CoreAccountID: account, MachineID: machineID, Expires: exp})
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		if err != nil {
			return Issued{}, ErrUnavailable
		}
		return Issued{Code: xbcodes.FormatVoucher(code), Expires: exp}, nil
	}
	return Issued{}, ErrUnavailable
}

// Limited reports whether machineID has used up its failed-attempt budget.
func (s *Service) Limited(machineID string) bool {
	s.init()
	return s.failures.Blocked(machineID)
}

// Fail records a failed attempt for machineID (wrong code or signup rejected).
func (s *Service) Fail(machineID string) {
	s.init()
	s.failures.Hit(machineID)
}

// Check is verifyvoucher: it validates a typed code for a device without
// consuming it. The account is the device's own, never taken from the caller.
// Failures count against a per-machine budget.
func (s *Service) Check(ctx context.Context, machineID, typed string) error {
	s.init()
	if !xbaccountapi.ValidMachineID(machineID) {
		return ErrInvalid
	}
	if s.Limited(machineID) {
		return ErrRateLimited
	}
	code, ok := xbcodes.NormalizeVoucher(typed)
	if !ok {
		s.Fail(machineID)
		return ErrBad
	}
	d, err := s.Store.GetDevice(ctx, machineID)
	if err != nil || d.Status != xbaccountapi.StatusActive || d.Signup != store.SignupAwaitingGamertag {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return ErrUnavailable
		}
		s.Fail(machineID)
		return ErrBad
	}
	switch err := s.Store.CheckVoucher(ctx, s.Hash(code), d.CoreAccountID, machineID); {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrVoucherUsed):
		s.Fail(machineID)
		return ErrUsed
	case errors.Is(err, store.ErrVoucherInvalid):
		s.Fail(machineID)
		return ErrBad
	default:
		return ErrUnavailable
	}
}
