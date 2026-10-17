// SPDX-License-Identifier: AGPL-3.0-only

package social

import "context"

// Answer is an invitee's reply to an invitation, kept for the inviter's next
// notification poll. Core carries invitations one way only, so answers live in
// this process (bounded, lost on restart: the inviter just sees no answer).
type Answer struct {
	XUID     string // who answered
	Payload  []byte // the invitation's own payload, so the inviter can match it
	Accepted bool
	At       int64
}

const maxAnswers = 32

// Delivered lists the unexpired invitations already handed to the viewer.
func (s *Service) Delivered(ctx context.Context, viewerXUID, gatewayAccount string) ([]Invite, error) {
	account, err := s.Actor(ctx, viewerXUID, gatewayAccount)
	if err != nil {
		return nil, err
	}
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Invite
	for _, e := range s.inbox[account] {
		if e.inv.Expires > now {
			out = append(out, e.inv)
		}
	}
	return out, nil
}

// AnswerInvite accepts or declines a delivered invitation and tells the inviter.
func (s *Service) AnswerInvite(ctx context.Context, viewerXUID, gatewayAccount, id string, accept bool) (Invite, error) {
	inv, err := s.AcceptInvite(ctx, viewerXUID, gatewayAccount, id) // also checks the viewer and the inbox
	if err != nil {
		return Invite{}, err
	}
	if !accept {
		if err := s.DeclineInvite(ctx, viewerXUID, gatewayAccount, id); err != nil {
			return Invite{}, err
		}
	}
	s.mu.Lock()
	if s.answers == nil {
		s.answers = map[string][]Answer{}
	}
	q := append(s.answers[inv.fromAccount], Answer{viewerXUID, inv.Payload, accept, s.now().Unix()})
	if len(q) > maxAnswers {
		q = q[len(q)-maxAnswers:]
	}
	s.answers[inv.fromAccount] = q
	s.mu.Unlock()
	if s.Hub != nil {
		s.Hub.Publish(Notice{Kind: NoticeAnswer, Account: inv.fromAccount, Subject: viewerXUID})
	}
	return inv, nil
}

// TakeAnswers returns and clears the answers to the viewer's invitations.
func (s *Service) TakeAnswers(ctx context.Context, viewerXUID, gatewayAccount string) ([]Answer, error) {
	account, err := s.Actor(ctx, viewerXUID, gatewayAccount)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.answers[account]
	delete(s.answers, account)
	return a, nil
}
