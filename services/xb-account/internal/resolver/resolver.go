// SPDX-License-Identifier: AGPL-3.0-only

// Package resolver implements xbaccountapi.Resolver and Revocations. It checks
// local principal status first (so revoked principals are denied even when
// core is slow) and then re-reads core: no positive result is cached.
package resolver

import (
	"context"
	"errors"
	"time"

	pb "openpak/xb-live/services/xb-account/internal/corepb"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-account/internal/core"
	"openpak/xb-live/services/xb-account/internal/store"
)

type Resolver struct {
	Core  core.API
	Store *store.Store
	// PollInterval is how often Poll rechecks the store while waiting.
	PollInterval time.Duration
}

var (
	_ xbaccountapi.Resolver    = (*Resolver)(nil)
	_ xbaccountapi.Revocations = (*Resolver)(nil)
)

func denied(k xbaccountapi.Kind, id, acct string, s xbaccountapi.Status) error {
	return &xbaccountapi.DeniedError{Principal: xbaccountapi.Principal{Kind: k, PrincipalID: id, CoreAccountID: acct, Status: s}}
}

func accountStatus(s pb.AccountStatus) xbaccountapi.Status {
	switch s {
	case pb.AccountStatus_ACCOUNT_STATUS_ACTIVE:
		return xbaccountapi.StatusActive
	case pb.AccountStatus_ACCOUNT_STATUS_BANNED:
		return xbaccountapi.StatusBanned
	default: // deletion pending, deleted, unspecified: never admit
		return xbaccountapi.StatusDeleted
	}
}

func coreErr(err error) error {
	if errors.Is(err, core.ErrNotFound) {
		return xbaccountapi.ErrNotFound
	}
	return xbaccountapi.ErrUnavailable
}

func (r *Resolver) ResolveUser(ctx context.Context, xuid string) (xbaccountapi.Principal, error) {
	if !xbaccountapi.ValidID(xuid) {
		return xbaccountapi.Principal{}, xbaccountapi.ErrInvalid
	}
	u, err := r.Store.GetUser(ctx, xuid)
	if errors.Is(err, store.ErrNotFound) {
		return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
	}
	if err != nil {
		return xbaccountapi.Principal{}, xbaccountapi.ErrUnavailable
	}
	if u.Status != xbaccountapi.StatusActive {
		return xbaccountapi.Principal{}, denied(xbaccountapi.KindUser, xuid, u.CoreAccountID, u.Status)
	}
	// Authoritative re-check: the link must still be active for this account.
	l, err := r.Core.GetLinkBySubject(ctx, xuid)
	switch {
	case errors.Is(err, core.ErrNotFound):
		return xbaccountapi.Principal{}, denied(xbaccountapi.KindUser, xuid, u.CoreAccountID, xbaccountapi.StatusUnlinked)
	case err != nil:
		return xbaccountapi.Principal{}, xbaccountapi.ErrUnavailable
	case l.State != pb.LinkState_LINK_STATE_ACTIVE || l.AccountID != u.CoreAccountID || (u.LinkID != "" && l.LinkID != u.LinkID):
		return xbaccountapi.Principal{}, denied(xbaccountapi.KindUser, xuid, u.CoreAccountID, xbaccountapi.StatusUnlinked)
	}
	if s, err := r.accountOK(ctx, u.CoreAccountID); err != nil {
		return xbaccountapi.Principal{}, err
	} else if s != xbaccountapi.StatusActive {
		return xbaccountapi.Principal{}, denied(xbaccountapi.KindUser, xuid, u.CoreAccountID, s)
	}
	return xbaccountapi.Principal{Kind: xbaccountapi.KindUser, PrincipalID: xuid, CoreAccountID: u.CoreAccountID, Status: xbaccountapi.StatusActive}, nil
}

// ResolveGamertag looks up the current gamertag alias, then applies exactly
// the ResolveUser checks to the XUID it names.
func (r *Resolver) ResolveGamertag(ctx context.Context, tag string) (xbaccountapi.Principal, error) {
	if !xbaccountapi.ValidGamertag(tag) {
		return xbaccountapi.Principal{}, xbaccountapi.ErrInvalid
	}
	u, err := r.Store.GetUserByGamertag(ctx, tag)
	if errors.Is(err, store.ErrNotFound) {
		return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
	}
	if err != nil {
		return xbaccountapi.Principal{}, xbaccountapi.ErrUnavailable
	}
	return r.ResolveUser(ctx, u.XUID)
}

func (r *Resolver) accountOK(ctx context.Context, id string) (xbaccountapi.Status, error) {
	a, err := r.Core.GetAccount(ctx, id)
	if errors.Is(err, core.ErrNotFound) {
		return xbaccountapi.StatusDeleted, nil
	}
	if err != nil {
		return "", xbaccountapi.ErrUnavailable
	}
	return accountStatus(a.Status), nil
}

func (r *Resolver) ResolveDevice(ctx context.Context, machineID string) (xbaccountapi.Principal, error) {
	if !xbaccountapi.ValidID(machineID) {
		return xbaccountapi.Principal{}, xbaccountapi.ErrInvalid
	}
	d, err := r.Store.GetDevice(ctx, machineID)
	if errors.Is(err, store.ErrNotFound) {
		return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
	}
	if err != nil {
		return xbaccountapi.Principal{}, xbaccountapi.ErrUnavailable
	}
	if d.Status != xbaccountapi.StatusActive {
		return xbaccountapi.Principal{}, denied(xbaccountapi.KindDevice, machineID, d.CoreAccountID, d.Status)
	}
	// A device is only as good as the account's Xbox link: no active link, no admission.
	if _, err := r.Core.GetActiveLinkByAccount(ctx, d.CoreAccountID); errors.Is(err, core.ErrNotFound) {
		return xbaccountapi.Principal{}, denied(xbaccountapi.KindDevice, machineID, d.CoreAccountID, xbaccountapi.StatusUnlinked)
	} else if err != nil {
		return xbaccountapi.Principal{}, coreErr(err)
	}
	if s, err := r.accountOK(ctx, d.CoreAccountID); err != nil {
		return xbaccountapi.Principal{}, err
	} else if s != xbaccountapi.StatusActive {
		return xbaccountapi.Principal{}, denied(xbaccountapi.KindDevice, machineID, d.CoreAccountID, s)
	}
	return xbaccountapi.Principal{Kind: xbaccountapi.KindDevice, PrincipalID: machineID, CoreAccountID: d.CoreAccountID, Status: xbaccountapi.StatusActive}, nil
}

func (r *Resolver) Poll(ctx context.Context, after uint64, limit int, wait time.Duration) ([]xbaccountapi.Revocation, error) {
	if limit < 1 || limit > xbaccountapi.MaxLimit {
		limit = xbaccountapi.MaxLimit
	}
	interval := r.PollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	deadline := time.Now().Add(wait)
	for {
		out, err := r.Store.Revocations(ctx, after, limit)
		if err != nil || len(out) > 0 || !time.Now().Before(deadline) {
			return out, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}
