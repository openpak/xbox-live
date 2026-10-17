// SPDX-License-Identifier: AGPL-3.0-only

package core

import (
	"context"
	"time"

	pb "openpak/xb-live/services/xb-social/internal/corepb"
)

// Relationship of the first account towards the second (core GetRelationship).
type Relationship int

const (
	RelNone Relationship = iota + 1
	RelPendingIncoming
	RelPendingOutgoing
	RelFriends
	RelBlockedBySelf
	RelBlockedByOther
)

type Blocked struct {
	AccountID, DisplayName string
	At                     int64
}

type Invitation struct {
	ID, From, FromName, TitleID, Nonce string
	Payload                            []byte
	Expires                            int64
}

// InvitationSummary is the non-consuming inbox view (no payload, no nonce).
type InvitationSummary struct {
	ID, From, FromName, TitleID, Namespace string
	Expires                                int64
}

type Event struct {
	Version                            uint64
	ID, Type, Account, Namespace, Subj string
	Created                            int64
}

// Backend is everything xb-social asks of account core.
type Backend interface {
	API

	ListIncoming(ctx context.Context, account string) ([]Friend, error)
	ListOutgoing(ctx context.Context, account string) ([]Friend, error)
	ListBlocks(ctx context.Context, account string) ([]Blocked, error)
	Relationship(ctx context.Context, account, other string) (Relationship, error)
	// CanInvite reports whether actor may invite target.
	CanInvite(ctx context.Context, actor, target string) (bool, error)
	RequestFriend(ctx context.Context, from, to, key string) error
	AcceptFriend(ctx context.Context, addressee, requester, key string) error
	RemoveFriend(ctx context.Context, account, other string) error
	Block(ctx context.Context, blocker, blocked string) error
	Unblock(ctx context.Context, blocker, blocked string) error

	// RegisterSession creates or replaces the live session of (account, xbox, title).
	RegisterSession(ctx context.Context, account, title, endpointRef string, lease time.Duration) (id string, applied time.Duration, err error)
	// Heartbeat renews; ErrNotFound when the session expired or is unknown.
	Heartbeat(ctx context.Context, id string) (time.Duration, error)
	ExpireSession(ctx context.Context, id string) error

	// ResolveSession returns the namespace of the session an invitation to
	// (account, title) would bind to; ErrNotFound when none is live.
	ResolveSession(ctx context.Context, account, title string) (namespace string, err error)
	SendInvitation(ctx context.Context, from, to, title string, payload []byte, ttl time.Duration) (id, nonce string, err error)
	PollInvitations(ctx context.Context, account string, limit int) ([]Invitation, error)
	AckInvitations(ctx context.Context, account string, ids, nonces []string) (int, error)
	ListInvitations(ctx context.Context, account string, limit int) ([]InvitationSummary, error)
	RejectInvitation(ctx context.Context, account, id string) (bool, error)

	// PollEvents returns events with version > since and the stream's highest version.
	PollEvents(ctx context.Context, since uint64, limit int) ([]Event, uint64, error)
}

func (c *Client) ListIncoming(p context.Context, account string) ([]Friend, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.social.ListIncomingRequests(ctx, &pb.ListIncomingRequestsRequest{AccountId: account})
	if err != nil {
		return nil, mapErr(err)
	}
	return friendsOf(r.Requesters), nil
}

func (c *Client) ListOutgoing(p context.Context, account string) ([]Friend, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.social.ListOutgoingRequests(ctx, &pb.ListOutgoingRequestsRequest{AccountId: account})
	if err != nil {
		return nil, mapErr(err)
	}
	return friendsOf(r.Addressees), nil
}

func friendsOf(in []*pb.Friend) []Friend {
	out := make([]Friend, 0, len(in))
	for _, f := range in {
		out = append(out, Friend{f.AccountId, f.DisplayName, f.LastSeenUnix, f.FriendsSinceUnix})
	}
	return out
}

func (c *Client) ListBlocks(p context.Context, account string) ([]Blocked, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.social.ListBlocks(ctx, &pb.ListBlocksRequest{AccountId: account})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Blocked, 0, len(r.Blocked))
	for _, b := range r.Blocked {
		out = append(out, Blocked{b.AccountId, b.DisplayName, b.BlockedAtUnix})
	}
	return out, nil
}

func (c *Client) Relationship(p context.Context, account, other string) (Relationship, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.social.GetRelationship(ctx, &pb.GetRelationshipRequest{AccountId: account, OtherId: other})
	if err != nil {
		return 0, mapErr(err)
	}
	switch r.Relationship {
	case pb.Relationship_RELATIONSHIP_NONE:
		return RelNone, nil
	case pb.Relationship_RELATIONSHIP_PENDING_INCOMING:
		return RelPendingIncoming, nil
	case pb.Relationship_RELATIONSHIP_PENDING_OUTGOING:
		return RelPendingOutgoing, nil
	case pb.Relationship_RELATIONSHIP_FRIENDS:
		return RelFriends, nil
	case pb.Relationship_RELATIONSHIP_BLOCKED_BY_SELF:
		return RelBlockedBySelf, nil
	case pb.Relationship_RELATIONSHIP_BLOCKED_BY_OTHER:
		return RelBlockedByOther, nil
	}
	return 0, ErrUnavailable // unknown answer: never guess
}

func (c *Client) CanInvite(p context.Context, actor, target string) (bool, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.social.CheckInteraction(ctx, &pb.CheckInteractionRequest{ActorId: actor, TargetId: target, Kind: pb.InteractionKind_INTERACTION_KIND_INVITE})
	if err != nil {
		return false, mapErr(err)
	}
	return r.Allowed, nil
}

func (c *Client) RequestFriend(p context.Context, from, to, key string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.social.RequestFriend(ctx, &pb.RequestFriendRequest{RequesterId: from, AddresseeId: to, IdempotencyKey: key})
	return mapNil(err)
}

func (c *Client) AcceptFriend(p context.Context, addressee, requester, key string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.social.AcceptFriend(ctx, &pb.AcceptFriendRequest{AddresseeId: addressee, RequesterId: requester, IdempotencyKey: key})
	return mapNil(err)
}

func (c *Client) RemoveFriend(p context.Context, account, other string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.social.RemoveFriend(ctx, &pb.RemoveFriendRequest{AccountId: account, OtherId: other})
	return mapNil(err)
}

func (c *Client) Block(p context.Context, blocker, blocked string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.social.Block(ctx, &pb.BlockRequest{BlockerId: blocker, BlockedId: blocked})
	return mapNil(err)
}

func (c *Client) Unblock(p context.Context, blocker, blocked string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.social.Unblock(ctx, &pb.UnblockRequest{BlockerId: blocker, BlockedId: blocked})
	return mapNil(err)
}

func mapNil(err error) error {
	if err == nil {
		return nil
	}
	return mapErr(err)
}

func (c *Client) RegisterSession(p context.Context, account, title, ref string, lease time.Duration) (string, time.Duration, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.sessions.RegisterSession(ctx, &pb.RegisterSessionRequest{AccountId: account, Namespace: Namespace,
		TitleId: title, EndpointRef: ref, LeaseSeconds: int32(lease / time.Second)})
	if err != nil {
		return "", 0, mapErr(err)
	}
	return r.SessionId, time.Duration(r.LeaseSeconds) * time.Second, nil
}

func (c *Client) Heartbeat(p context.Context, id string) (time.Duration, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.sessions.Heartbeat(ctx, &pb.HeartbeatRequest{SessionId: id})
	if err != nil {
		return 0, mapErr(err)
	}
	return time.Duration(r.LeaseSeconds) * time.Second, nil
}

func (c *Client) ExpireSession(p context.Context, id string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.sessions.ExpireSession(ctx, &pb.ExpireSessionRequest{SessionId: id})
	return mapNil(err)
}

func (c *Client) SendInvitation(p context.Context, from, to, title string, payload []byte, ttl time.Duration) (string, string, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.invites.SendInvitation(ctx, &pb.SendInvitationRequest{FromAccountId: from, ToAccountId: to, TitleId: title,
		Payload: payload, TtlSeconds: int32(ttl / time.Second)})
	if err != nil {
		return "", "", mapErr(err)
	}
	return r.InvitationId, r.Nonce, nil
}

func (c *Client) PollInvitations(p context.Context, account string, limit int) ([]Invitation, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.invites.PollInvitations(ctx, &pb.PollInvitationsRequest{Namespace: Namespace, AccountId: account, Limit: int32(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Invitation, 0, len(r.Invitations))
	for _, i := range r.Invitations {
		out = append(out, Invitation{i.InvitationId, i.FromAccountId, i.FromDisplayName, i.TitleId, i.Nonce, i.Payload, i.ExpiresAtUnix})
	}
	return out, nil
}

func (c *Client) AckInvitations(p context.Context, account string, ids, nonces []string) (int, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.invites.AckInvitations(ctx, &pb.AckInvitationsRequest{Namespace: Namespace, AccountId: account, InvitationIds: ids, Nonces: nonces})
	if err != nil {
		return 0, mapErr(err)
	}
	return int(r.Acked), nil
}

func (c *Client) ListInvitations(p context.Context, account string, limit int) ([]InvitationSummary, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.invites.ListInvitations(ctx, &pb.ListInvitationsRequest{AccountId: account, Limit: int32(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]InvitationSummary, 0, len(r.Invitations))
	for _, i := range r.Invitations {
		out = append(out, InvitationSummary{i.InvitationId, i.FromAccountId, i.FromDisplayName, i.TitleId, i.Namespace, i.ExpiresAtUnix})
	}
	return out, nil
}

func (c *Client) RejectInvitation(p context.Context, account, id string) (bool, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.invites.RejectInvitation(ctx, &pb.RejectInvitationRequest{AccountId: account, InvitationId: id})
	if err != nil {
		return false, mapErr(err)
	}
	return r.Rejected, nil
}

func (c *Client) PollEvents(p context.Context, since uint64, limit int) ([]Event, uint64, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.events.PollEvents(ctx, &pb.PollEventsRequest{SinceVersion: since, Limit: int32(limit)})
	if err != nil {
		return nil, 0, mapErr(err)
	}
	out := make([]Event, 0, len(r.Events))
	for _, e := range r.Events {
		out = append(out, Event{e.Version, e.EventId, e.Type, e.AccountId, e.Namespace, e.SubjectId, e.CreatedAtUnix})
	}
	return out, r.MaxVersion, nil
}

func (c *Client) ResolveSession(p context.Context, account, title string) (string, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.sessions.ResolveSession(ctx, &pb.ResolveSessionRequest{AccountId: account, TitleId: title})
	if err != nil {
		return "", mapErr(err)
	}
	return r.Namespace, nil
}
