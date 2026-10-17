// SPDX-License-Identifier: AGPL-3.0-only

package social

import (
	"context"
	"errors"
	"sync"
	"time"

	"openpak/xb-live/services/xb-social/internal/core"
)

const (
	// MaxInvitePayload is core's cap on the opaque invitation payload.
	MaxInvitePayload = 4096
	// DefaultInviteTTL is how long an invitation stays valid when the caller gives none.
	DefaultInviteTTL = 5 * time.Minute
	pollBatch        = 100
)

// SendInvite invites a friend into the title the viewer is playing. Both sides
// must be online in the same Xbox title: core binds an invitation to the
// target's live session in that title, and another console's session with the
// same title number is never a target. payload is opaque and delivered as is.
func (s *Service) SendInvite(ctx context.Context, viewerXUID, gatewayAccount, targetXUID string, title uint32, payload []byte, ttl time.Duration) error {
	if title == 0 || len(payload) == 0 || len(payload) > MaxInvitePayload {
		return ErrInvalid
	}
	if ttl <= 0 {
		ttl = DefaultInviteTTL
	}
	actor, target, err := s.pair(ctx, viewerXUID, gatewayAccount, targetXUID)
	if err != nil {
		return err
	}
	key := TitleKey(title)
	if s.Presence != nil {
		if t, ok := s.Presence.Current(actor); !ok || t != key {
			return ErrNotReachable // you can only invite from inside the title
		}
	}
	// Check policy first so a block or non-friendship is not reported as "offline".
	ok, err := s.Core.CanInvite(ctx, actor, target)
	switch {
	case errors.Is(err, core.ErrNotFound):
		return ErrUnknownUser
	case err != nil:
		return ErrUnavailable
	case !ok:
		return ErrNotPermitted
	}
	// The invitation binds to whatever session core resolves for (target,
	// title), whatever its platform; only an Xbox one can be delivered here.
	ns, err := s.Core.ResolveSession(ctx, target, key)
	switch {
	case errors.Is(err, core.ErrNotFound):
		return ErrNotReachable
	case err != nil:
		return ErrUnavailable
	case ns != core.Namespace:
		return ErrNotReachable
	}
	_, _, err = s.Core.SendInvitation(ctx, actor, target, key, payload, ttl)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrConflict):
		return ErrNotReachable // the session ended between the check and the send
	case errors.Is(err, core.ErrDenied):
		return ErrNotPermitted
	case errors.Is(err, core.ErrInvalid):
		return ErrInvalid
	}
	return ErrUnavailable
}

// PollInvites delivers the viewer's waiting invitations through deliver and
// acknowledges them in core only after deliver succeeded, so delivery is
// at-least-once on the wire and exactly-once as far as core's state goes. It is
// idempotent: an invitation already handed over (including one whose ack
// failed) is not delivered twice; its ack is simply retried. Invitations from
// senders with no Xbox identity are not delivered (and not acknowledged: they
// expire by their own TTL). It returns the number delivered.
func (s *Service) PollInvites(ctx context.Context, viewerXUID, gatewayAccount string, deliver func([]Invite) error) (int, error) {
	account, err := s.Actor(ctx, viewerXUID, gatewayAccount)
	if err != nil {
		return 0, err
	}
	mu, _ := s.polling.LoadOrStore(account, &sync.Mutex{})
	mu.(*sync.Mutex).Lock() // one poll per account at a time, or two could both deliver
	defer mu.(*sync.Mutex).Unlock()
	raw, err := s.Core.PollInvitations(ctx, account, pollBatch)
	if err != nil {
		return 0, ErrUnavailable
	}
	s.mu.Lock()
	box := s.boxLocked(account)
	var fresh []core.Invitation
	var retry []*inboxEntry
	for _, in := range raw {
		if e, ok := box[in.ID]; ok {
			retry = append(retry, e) // handed over before: ack (again) but never deliver twice
			continue
		}
		fresh = append(fresh, in)
	}
	s.mu.Unlock()

	var ids []string
	for _, in := range fresh {
		ids = append(ids, in.From)
	}
	ppl, err := s.people(ctx, dedupe(ids))
	if err != nil {
		return 0, err
	}
	var batch []Invite
	for _, in := range fresh {
		p, ok := ppl[in.From]
		if !ok || in.From == account {
			continue
		}
		batch = append(batch, Invite{ID: in.ID, From: p, TitleID: in.TitleID, Expires: in.Expires, Payload: in.Payload, nonce: in.Nonce, fromAccount: in.From})
	}
	if len(batch) > 0 {
		if err := deliver(batch); err != nil {
			return 0, err // nothing acked: core redelivers after its window
		}
		s.mu.Lock()
		for _, inv := range batch {
			box[inv.ID] = &inboxEntry{inv: inv}
			retry = append(retry, box[inv.ID])
		}
		s.mu.Unlock()
	}
	// Ack everything handed over, including earlier acks that failed.
	var ackIDs, nonces []string
	s.mu.Lock()
	for _, e := range retry {
		ackIDs = append(ackIDs, e.inv.ID)
		nonces = append(nonces, e.inv.nonce)
	}
	s.mu.Unlock()
	if len(ackIDs) > 0 {
		if _, err := s.Core.AckInvitations(ctx, account, ackIDs, nonces); err != nil {
			return len(batch), ErrUnavailable // delivered; the next poll retries the ack
		}
		s.mu.Lock()
		for _, id := range ackIDs {
			if e := box[id]; e != nil {
				e.acked = true
			}
		}
		s.mu.Unlock()
	}
	s.reap(account)
	return len(batch), nil
}

func (s *Service) boxLocked(account string) map[string]*inboxEntry {
	if s.inbox == nil {
		s.inbox = map[string]map[string]*inboxEntry{}
	}
	b := s.inbox[account]
	if b == nil {
		b = map[string]*inboxEntry{}
		s.inbox[account] = b
	}
	return b
}

// reap forgets delivered invitations once they have expired.
func (s *Service) reap(account string) {
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.inbox[account] {
		if e.acked && e.inv.Expires <= now {
			delete(s.inbox[account], id)
		}
	}
}

// AcceptInvite returns a delivered, unexpired invitation so the console can
// join its sender. The invitation must have been delivered to this viewer by
// PollInvites (the nonce and payload live only there).
func (s *Service) AcceptInvite(ctx context.Context, viewerXUID, gatewayAccount, id string) (Invite, error) {
	account, err := s.Actor(ctx, viewerXUID, gatewayAccount)
	if err != nil {
		return Invite{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.inbox[account][id]
	if e == nil || e.inv.Expires <= s.now().Unix() {
		return Invite{}, ErrNoInvite
	}
	return e.inv, nil
}

// DeclineInvite declines an invitation. Core can reject only a still pending
// one; a delivered one is simply forgotten (the sender is not told either way).
func (s *Service) DeclineInvite(ctx context.Context, viewerXUID, gatewayAccount, id string) error {
	account, err := s.Actor(ctx, viewerXUID, gatewayAccount)
	if err != nil {
		return err
	}
	s.mu.Lock()
	_, known := s.inbox[account][id]
	delete(s.inbox[account], id)
	s.mu.Unlock()
	rejected, err := s.Core.RejectInvitation(ctx, account, id)
	switch {
	case err == nil && (rejected || known):
		return nil
	case err == nil, errors.Is(err, core.ErrNotFound):
		return ErrNoInvite
	case errors.Is(err, core.ErrInvalid):
		return ErrNoInvite
	}
	if known {
		return nil
	}
	return ErrUnavailable
}
