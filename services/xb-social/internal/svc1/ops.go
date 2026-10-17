// SPDX-License-Identifier: AGPL-3.0-only

package svc1

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strconv"

	"openpak/xb-live/services/xb-social/internal/social"
)

// Operation message types on xpresence.srf (docs/xbox/social-protocol.md 3).
const (
	opFriendRequest = 0x3ec
	opRemove        = 0x3ed
	opDecline       = 0x3ee
	opAcceptBlock   = 0x3ef
	opSendInvite    = 0x3f3
	opAnswerInvite  = 0x3f4
)

// Status values the console interprets in X-Err (section 4). The operation
// replies carry no body; this header is the whole answer.
const (
	hrListFull        = 0x80152002
	hrAlreadyPending  = 0x80152004
	hrAlreadyFriend   = 0x80152007
	hrNotFound        = 0x80152008
	hrSelf            = 0x8015200a
	hrCannot          = 0x8015200b
	hrNoPresenceSess  = 0x8015200c
	maxInviteTargets  = 100
	invitePayloadSize = 16 // session id u64 + sent time u64 (unix seconds)
)

func xerr(code uint32) (result, error) { return result{xerr: code}, nil }

// operation executes a friend or invitation operation for the bound user. All
// layouts start with the sender's XUID, which must be the connection's.
func (s *Server) operation(ctx context.Context, c Call, typ uint32, msg []byte) (result, error) {
	body := msg[presenceHeader:]
	var want int // exact body length; -1 = variable
	switch typ {
	case opFriendRequest:
		want = 0x12
	case opRemove, opDecline:
		want = 0x10
	case opAcceptBlock:
		want = 0x14
	case opSendInvite:
		want = -1
	case opAnswerInvite:
		want = 0x1a
	default:
		if s.Messages == nil {
			return result{}, ErrUnsupported
		}
		if _, err := s.Social.Actor(ctx, c.XUID, c.Info.CoreAccountID); err != nil {
			return result{}, err
		}
		out, err := s.Messages.Handle(ctx, c, typ, [presenceHeader]byte(msg[:presenceHeader]), body)
		return result{body: out}, err
	}
	if len(body) < 8 || (want >= 0 && len(body) != want) || binary.LittleEndian.Uint64(body) != c.Info.XUID {
		return result{}, errBad
	}
	u := func(off int) string { return fmt.Sprintf("%016x", binary.LittleEndian.Uint64(body[off:])) }
	svc, acct := s.Social, c.Info.CoreAccountID
	switch typ {
	case opFriendRequest:
		if r, err := svc.Roster(ctx, c.XUID, acct); err != nil {
			return result{}, err
		} else if r.BuddyCount() >= maxBuddies {
			return xerr(hrListFull)
		}
		o, err := svc.SendFriendRequest(ctx, c.XUID, acct, u(8))
		if err == nil && o == social.AlreadyFriends {
			return xerr(hrAlreadyFriend)
		}
		return opResult(err)
	case opRemove:
		err := svc.RemoveFriend(ctx, c.XUID, acct, u(8))
		if errors.Is(err, social.ErrNotFriends) { // "remove / cancel": a request of ours
			err = svc.CancelFriendRequest(ctx, c.XUID, acct, u(8))
		}
		return opResult(err)
	case opDecline:
		return opResult(svc.DeclineFriendRequest(ctx, c.XUID, acct, u(8)))
	case opAcceptBlock:
		switch binary.LittleEndian.Uint32(body[16:]) {
		case 0:
			return opResult(svc.AcceptFriendRequest(ctx, c.XUID, acct, u(8)))
		case 1:
			return opResult(svc.Block(ctx, c.XUID, acct, u(8)))
		}
		return result{}, errBad
	case opSendInvite:
		return s.sendInvite(ctx, c, body)
	case opAnswerInvite:
		inviter, session, answer := u(8), binary.LittleEndian.Uint64(body[16:]), binary.LittleEndian.Uint16(body[24:])
		if answer > 1 {
			return result{}, errBad
		}
		inbox, err := svc.Delivered(ctx, c.XUID, acct)
		if err != nil {
			return result{}, err
		}
		for _, in := range inbox {
			if in.From.XUID == inviter && len(in.Payload) == invitePayloadSize && binary.LittleEndian.Uint64(in.Payload) == session {
				_, err := svc.AnswerInvite(ctx, c.XUID, acct, in.ID, answer == 1)
				return opResult(err)
			}
		}
		return xerr(hrNotFound)
	}
	return result{}, ErrUnsupported
}

// opResult maps a domain outcome to the console's status. Failures that would
// reveal more than the console may know (a block, a policy refusal) read as
// "not found".
func opResult(err error) (result, error) {
	if err != nil {
		log.Printf("svc1: operation refused: %v", err)
	}
	switch {
	case err == nil:
		return result{}, nil
	case errors.Is(err, social.ErrInvalid):
		return xerr(hrSelf)
	case errors.Is(err, social.ErrUnknownUser), errors.Is(err, social.ErrNoRequest), errors.Is(err, social.ErrNotFriends),
		errors.Is(err, social.ErrNotPermitted), errors.Is(err, social.ErrNoInvite):
		return xerr(hrNotFound)
	case errors.Is(err, social.ErrBlocked):
		return xerr(hrCannot)
	case errors.Is(err, social.ErrNotReachable):
		return xerr(hrNoPresenceSess)
	}
	return result{}, err
}

// sendInvite: session id u64, n u16, n XUIDs (n = 0 means every friend who is
// in the sender's title). The payload core carries is the session id and the
// send time, which the recipient's notification record is rebuilt from.
func (s *Server) sendInvite(ctx context.Context, c Call, body []byte) (result, error) {
	if len(body) < 18 {
		return result{}, errBad
	}
	session := binary.LittleEndian.Uint64(body[8:])
	n := int(binary.LittleEndian.Uint16(body[16:]))
	if n > maxInviteTargets || len(body) != 18+8*n {
		return result{}, errBad
	}
	acct := c.Info.CoreAccountID
	account, err := s.Social.Actor(ctx, c.XUID, acct)
	if err != nil {
		return result{}, err
	}
	key, ok := s.Presence.Current(account)
	if !ok || key == "" {
		return xerr(hrNoPresenceSess)
	}
	title64, err := strconv.ParseUint(key, 16, 32)
	if err != nil {
		return result{}, errBad
	}
	var targets []string
	for i := range n {
		targets = append(targets, fmt.Sprintf("%016x", binary.LittleEndian.Uint64(body[18+8*i:])))
	}
	if n == 0 {
		r, err := s.Social.RosterOf(ctx, account)
		if err != nil {
			return result{}, err
		}
		for _, f := range r.Friends {
			if f.Presence.State == "online" && f.Presence.TitleID == key {
				targets = append(targets, f.XUID)
			}
		}
		if len(targets) == 0 {
			return xerr(hrNoPresenceSess)
		}
	}
	payload := binary.LittleEndian.AppendUint64(nil, session)
	payload = binary.LittleEndian.AppendUint64(payload, uint64(s.now().Unix()))
	sent := 0
	var first error
	for _, t := range targets {
		err := s.Social.SendInvite(ctx, c.XUID, acct, t, uint32(title64), payload, 0)
		if err == nil {
			sent++
		} else if first == nil {
			first = err
		}
	}
	if sent > 0 {
		return result{}, nil // partial delivery is delivery; the console cannot be told per friend
	}
	return opResult(first)
}
