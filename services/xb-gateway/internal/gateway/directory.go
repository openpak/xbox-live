// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
)

// AccountDirectory adapts the xb-account contract (internal/xbaccountapi) to
// Directory. Anything other than an active principal is a denial.
type AccountDirectory struct{ Resolver xbaccountapi.Resolver }

func (d AccountDirectory) ResolveUser(ctx context.Context, xuid uint64) (Principal, error) {
	p, err := d.Resolver.ResolveUser(ctx, fmt.Sprintf("%016x", xuid))
	if err != nil {
		return Principal{}, err
	}
	return Principal{PrincipalID: p.PrincipalID, CoreAccountID: p.CoreAccountID, Active: p.Status == xbaccountapi.StatusActive}, nil
}

// Check probes reachability with an identifier that should not exist: "not
// found" proves the service answered; any other error means unavailable.
func (d AccountDirectory) Check(ctx context.Context) error {
	_, err := d.Resolver.ResolveUser(ctx, "0000000000000001")
	if err == nil || errors.Is(err, xbaccountapi.ErrNotFound) || errors.Is(err, xbaccountapi.ErrDenied) {
		return nil
	}
	return err
}

// RevokeAccount closes every session bound to a core account.
func (s *Server) RevokeAccount(coreAccountID string) int {
	s.mu.RLock()
	var hit []*Session
	for _, sess := range s.sessions {
		if sess.identity.Principal.CoreAccountID == coreAccountID {
			hit = append(hit, sess)
		}
	}
	s.mu.RUnlock()
	for _, sess := range hit {
		s.closeSession(sess, "revoked", true)
	}
	return len(hit)
}

// FollowRevocations applies the xb-account revocation stream until ctx ends.
// Delivery is at-least-once; closing an already closed session is harmless.
// Sessions are memory-only, so starting from cursor 0 after a restart is safe.
func (s *Server) FollowRevocations(ctx context.Context, rev xbaccountapi.Revocations) {
	var cursor uint64
	for ctx.Err() == nil {
		items, err := rev.Poll(ctx, cursor, 100, 20*time.Second)
		if err != nil {
			s.log.Warn("revocation poll failed", "err", err.Error())
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
			continue
		}
		for _, r := range items {
			switch r.Scope {
			case xbaccountapi.ScopeUser:
				s.RevokePrincipal(r.PrincipalID)
			case xbaccountapi.ScopeAccount:
				s.RevokeAccount(r.CoreAccountID)
			}
			cursor = max(cursor, r.Seq)
		}
	}
}
