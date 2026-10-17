// SPDX-License-Identifier: AGPL-3.0-only

package svc1

import (
	"context"
	"encoding/binary"
	"strconv"

	"openpak/xb-live/services/xb-social/internal/friends"
	"openpak/xb-live/services/xb-social/internal/social"
)

// Notification poll (docs/xbox/social-protocol.md 2): type 8, body xuid u64,
// kind u16, u32 0, u16 0x14, u32 max size. Kinds: 0/1 friend list changes,
// 2 presence, 3 invitations received, 4 invitation answers.
const (
	msgNotifyPoll  = 8
	notifyReplyTyp = 0x44e // the client has not been seen checking this (RE); unverified
	// Record body layouts, by kind.
	listRecBody   = 0x14
	presRecBody   = 0x1c
	inviteRecBody = 0x1c
	answerRecBody = 0x1a

	opListConfirmed = 3
	opListSent      = 1
	opListReceived  = 2

	flagOnline  = 0x1
	flagPlaying = 0x4
	// Windows FILETIME of the unix epoch, 100 ns units.
	filetimeUnixEpoch = 116444736000000000
)

func (s *Server) notification(ctx context.Context, c Call, body []byte) (result, error) {
	msgs, err := splitMessages(body, 1)
	if err != nil {
		return result{}, err
	}
	m := msgs[0]
	if binary.LittleEndian.Uint32(m[0:4]) != msgNotifyPoll {
		return result{}, ErrUnsupported
	}
	b := m[presenceHeader:]
	if len(b) != 0x14 || binary.LittleEndian.Uint64(b) != c.Info.XUID {
		return result{}, errBad
	}
	kind := binary.LittleEndian.Uint16(b[8:])
	if kind > 4 {
		return result{}, errBad
	}
	acct := c.Info.CoreAccountID
	var recs [][]byte
	rec := func(body []byte) {
		r := binary.LittleEndian.AppendUint32(nil, 0)
		r = binary.LittleEndian.AppendUint16(r, uint16(len(body)))
		recs = append(recs, append(r, body...))
	}
	switch kind {
	case 0, 1:
		r, err := s.Social.Roster(ctx, c.XUID, acct)
		if err != nil {
			return result{}, err
		}
		// Current state as list operations; entries that were removed are
		// conveyed by the AliveReply list replacement, not here.
		stamp := uint32(s.now().Unix())
		add := func(xuid, name string, op uint16) {
			x, err := strconv.ParseUint(xuid, 16, 64)
			if err != nil || x == 0 || len(name) < 1 || len(name) > 16 {
				return
			}
			bd := binary.LittleEndian.AppendUint32(nil, stamp)
			bd = binary.LittleEndian.AppendUint64(bd, x)
			bd = binary.LittleEndian.AppendUint16(bd, op)
			bd = binary.LittleEndian.AppendUint32(bd, 0)
			bd = binary.LittleEndian.AppendUint16(bd, uint16(len(name)))
			rec(append(bd, name...))
		}
		for _, f := range r.Friends {
			add(f.XUID, f.Gamertag, opListConfirmed)
		}
		for _, p := range r.Incoming {
			add(p.XUID, p.Gamertag, opListReceived)
		}
		for _, p := range r.Outgoing {
			add(p.XUID, p.Gamertag, opListSent)
		}
	case 2:
		r, err := s.Social.Roster(ctx, c.XUID, acct)
		if err != nil {
			return result{}, err
		}
		for _, f := range r.Friends {
			x, err := strconv.ParseUint(f.XUID, 16, 64)
			if err != nil || x == 0 || f.Presence.State != friends.Online {
				continue
			}
			var title uint64
			flags := uint32(flagOnline)
			if f.Presence.TitleID != "" {
				if title, err = strconv.ParseUint(f.Presence.TitleID, 16, 32); err == nil {
					flags |= flagPlaying
				}
			}
			bd := binary.LittleEndian.AppendUint64(nil, x)
			bd = binary.LittleEndian.AppendUint32(bd, uint32(title))
			bd = binary.LittleEndian.AppendUint32(bd, flags)
			bd = binary.LittleEndian.AppendUint64(bd, 0) // session id: no match session is published
			bd = binary.LittleEndian.AppendUint16(bd, 0)
			bd = binary.LittleEndian.AppendUint16(bd, 0)
			rec(bd)
		}
	case 3:
		_, err := s.Social.PollInvites(ctx, c.XUID, acct, func(in []social.Invite) error {
			for _, i := range in {
				x, err1 := strconv.ParseUint(i.From.XUID, 16, 64)
				title, err2 := strconv.ParseUint(i.TitleID, 16, 32)
				if err1 != nil || err2 != nil || len(i.Payload) != invitePayloadSize {
					continue // not an invitation this service wrote
				}
				bd := binary.LittleEndian.AppendUint64(nil, x)
				bd = binary.LittleEndian.AppendUint64(bd, binary.LittleEndian.Uint64(i.Payload))
				bd = binary.LittleEndian.AppendUint32(bd, uint32(title))
				sent := binary.LittleEndian.Uint64(i.Payload[8:])
				bd = binary.LittleEndian.AppendUint64(bd, sent*10_000_000+filetimeUnixEpoch)
				rec(bd)
			}
			return nil
		})
		if err != nil {
			return result{}, err
		}
	case 4:
		as, err := s.Social.TakeAnswers(ctx, c.XUID, acct)
		if err != nil {
			return result{}, err
		}
		for _, a := range as {
			x, err := strconv.ParseUint(a.XUID, 16, 64)
			if err != nil || x == 0 {
				continue
			}
			bd := binary.LittleEndian.AppendUint64(nil, x)
			bd = append(bd, make([]byte, answerRecBody-8)...)
			if a.Accepted {
				binary.LittleEndian.PutUint16(bd[0x18:], 1)
			}
			rec(bd)
		}
	}
	// The poll answers the pending bit of its kind: clear it with a higher version
	// (version words are applied only when newer) and hand back the vector.
	var words []uint32
	if s.Notifier != nil {
		bit := map[uint16]uint32{0: social.BitList, 1: social.BitList, 3: social.BitInvite, 4: social.BitAnswer}[kind]
		words = s.Notifier.Take(c.XUID, bit)
	}
	// Header, then: xuid u64, kind u16, HR s32, 6 unread bytes, record count u16,
	// 4 unread, N s32 version words, the words, records.
	out := make([]byte, presenceHeader, presenceHeader+0x1e)
	binary.LittleEndian.PutUint32(out[0:], notifyReplyTyp)
	copy(out[8:presenceHeader], m[8:presenceHeader])
	out = binary.LittleEndian.AppendUint64(out, c.Info.XUID)
	out = binary.LittleEndian.AppendUint16(out, kind)
	out = binary.LittleEndian.AppendUint32(out, 0)
	out = append(out, make([]byte, 6)...)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(recs)))
	out = append(out, make([]byte, 4)...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(words)))
	for _, w := range words {
		out = binary.LittleEndian.AppendUint32(out, w)
	}
	for _, r := range recs {
		out = append(out, r...)
	}
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)-presenceHeader))
	return result{body: out}, nil
}
