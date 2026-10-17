// SPDX-License-Identifier: AGPL-3.0-only

package social

import (
	"context"
	"errors"

	"openpak/xb-live/services/xb-social/internal/core"
)

// Outcome of SendFriendRequest.
type Outcome string

const (
	Requested      Outcome = "requested"       // pending until the addressee accepts
	Accepted       Outcome = "accepted"        // they had already asked us: now friends
	AlreadyFriends Outcome = "already_friends" // nothing to do
)

func opErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrNotFound):
		return ErrUnknownUser
	case errors.Is(err, core.ErrInvalid):
		return ErrInvalid
	case errors.Is(err, core.ErrDenied), errors.Is(err, core.ErrConflict):
		return ErrNotPermitted
	}
	return ErrUnavailable
}

func (s *Service) rel(ctx context.Context, actor, other string) (core.Relationship, error) {
	r, err := s.Core.Relationship(ctx, actor, other)
	if err != nil {
		return 0, opErr(err)
	}
	return r, nil
}

// SendFriendRequest asks target to be the viewer's friend. It is idempotent,
// and a request that crosses an incoming one becomes an acceptance.
func (s *Service) SendFriendRequest(ctx context.Context, viewerXUID, gatewayAccount, targetXUID string) (Outcome, error) {
	actor, err := s.Actor(ctx, viewerXUID, gatewayAccount)
	if err != nil {
		return "", err
	}
	target, err := s.peer(ctx, actor, targetXUID)
	if err != nil {
		return "", err
	}
	r, err := s.rel(ctx, actor, target)
	if err != nil {
		return "", err
	}
	switch r {
	case core.RelFriends:
		return AlreadyFriends, nil
	case core.RelPendingOutgoing:
		return Requested, nil
	case core.RelBlockedBySelf:
		return "", ErrBlocked
	case core.RelBlockedByOther:
		return "", ErrUnknownUser // never reveal who blocked whom
	case core.RelPendingIncoming:
		if err := s.Core.AcceptFriend(ctx, actor, target, "xb:accept:"+actor+":"+target); err != nil {
			return "", opErr(err)
		}
		return Accepted, nil
	case core.RelNone:
		if err := s.Core.RequestFriend(ctx, actor, target, "xb:request:"+actor+":"+target); err != nil {
			return "", opErr(err)
		}
		return Requested, nil
	}
	return "", ErrUnavailable
}

// AcceptFriendRequest accepts the pending request from requesterXUID.
func (s *Service) AcceptFriendRequest(ctx context.Context, viewerXUID, gatewayAccount, requesterXUID string) error {
	actor, other, err := s.pair(ctx, viewerXUID, gatewayAccount, requesterXUID)
	if err != nil {
		return err
	}
	r, err := s.rel(ctx, actor, other)
	if err != nil {
		return err
	}
	switch r {
	case core.RelFriends:
		return nil // idempotent
	case core.RelPendingIncoming:
		return opErr(s.Core.AcceptFriend(ctx, actor, other, "xb:accept:"+actor+":"+other))
	}
	return ErrNoRequest
}

// DeclineFriendRequest drops the pending request from requesterXUID.
func (s *Service) DeclineFriendRequest(ctx context.Context, viewerXUID, gatewayAccount, requesterXUID string) error {
	return s.dropPending(ctx, viewerXUID, gatewayAccount, requesterXUID, core.RelPendingIncoming)
}

// CancelFriendRequest withdraws the viewer's own pending request.
func (s *Service) CancelFriendRequest(ctx context.Context, viewerXUID, gatewayAccount, targetXUID string) error {
	return s.dropPending(ctx, viewerXUID, gatewayAccount, targetXUID, core.RelPendingOutgoing)
}

func (s *Service) dropPending(ctx context.Context, viewerXUID, gatewayAccount, otherXUID string, want core.Relationship) error {
	actor, other, err := s.pair(ctx, viewerXUID, gatewayAccount, otherXUID)
	if err != nil {
		return err
	}
	r, err := s.rel(ctx, actor, other)
	if err != nil {
		return err
	}
	if r != want {
		return ErrNoRequest // never turn "decline" into "unfriend"
	}
	return opErr(s.Core.RemoveFriend(ctx, actor, other))
}

// RemoveFriend ends an accepted friendship.
func (s *Service) RemoveFriend(ctx context.Context, viewerXUID, gatewayAccount, friendXUID string) error {
	actor, other, err := s.pair(ctx, viewerXUID, gatewayAccount, friendXUID)
	if err != nil {
		return err
	}
	r, err := s.rel(ctx, actor, other)
	if err != nil {
		return err
	}
	if r != core.RelFriends {
		return ErrNotFriends
	}
	return opErr(s.Core.RemoveFriend(ctx, actor, other))
}

// Block blocks target: the block is recorded first (it is what enforces), then
// any friendship or pending request in either direction is removed, as native
// blocking does. If the removal fails the block still holds and the error is
// reported.
func (s *Service) Block(ctx context.Context, viewerXUID, gatewayAccount, targetXUID string) error {
	actor, other, err := s.pair(ctx, viewerXUID, gatewayAccount, targetXUID)
	if err != nil {
		return err
	}
	if err := s.Core.Block(ctx, actor, other); err != nil {
		return opErr(err)
	}
	return opErr(s.Core.RemoveFriend(ctx, actor, other))
}

// Unblock lifts the viewer's block. It does not restore a friendship.
func (s *Service) Unblock(ctx context.Context, viewerXUID, gatewayAccount, targetXUID string) error {
	actor, other, err := s.pair(ctx, viewerXUID, gatewayAccount, targetXUID)
	if err != nil {
		return err
	}
	return opErr(s.Core.Unblock(ctx, actor, other))
}

func (s *Service) pair(ctx context.Context, viewerXUID, gatewayAccount, otherXUID string) (actor, other string, err error) {
	if actor, err = s.Actor(ctx, viewerXUID, gatewayAccount); err != nil {
		return "", "", err
	}
	if other, err = s.peer(ctx, actor, otherXUID); err != nil {
		return "", "", err
	}
	return actor, other, nil
}
