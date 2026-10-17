// SPDX-License-Identifier: AGPL-3.0-only

// Package core is xb-social's client of account core: the canonical friend
// graph (Social), live sessions and invitations (Sessions, Invitations), the
// durable event stream (Events) and adapter links (Links). Core stays the only
// authority; xb-social keeps no copy of the graph, only the session ids of the
// leases it published itself.
package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	pb "openpak/xb-live/services/xb-social/internal/corepb"
)

// Namespace of native Xbox links in account core ("xbox", never "xbl").
const Namespace = "xbox"

var (
	ErrNotFound    = errors.New("core: not found")
	ErrUnavailable = errors.New("core: unavailable")
	// ErrInvalid: core rejected the request as malformed (InvalidArgument, e.g. self request).
	ErrInvalid = errors.New("core: invalid request")
	// ErrDenied: core policy refused (PermissionDenied: blocks, not friends).
	ErrDenied = errors.New("core: denied")
	// ErrConflict: the request does not fit the current state (FailedPrecondition:
	// not pending, reverse request pending, blocked, no live session).
	ErrConflict = errors.New("core: state conflict")
)

type Friend struct {
	AccountID   string
	DisplayName string
	LastSeen    int64 // unix, 0 unknown
	Since       int64 // unix, 0 unknown
}

type Link struct{ SubjectID, PublicCode string }

type Presence struct {
	AccountID, Namespace, TitleID string
	SinceUnix                     int64
}

// API is what the friends projection needs from core.
type API interface {
	ListFriends(ctx context.Context, account string) ([]Friend, error)
	// ActiveLink returns the account's active Xbox link, or ErrNotFound.
	ActiveLink(ctx context.Context, account string) (Link, error)
	GetPresence(ctx context.Context, accounts []string) ([]Presence, error)
	// CanDiscover reports whether actor may see target's presence.
	CanDiscover(ctx context.Context, actor, target string) (bool, error)
}

type Client struct {
	social   pb.SocialClient
	sessions pb.SessionsClient
	links    pb.LinksClient
	invites  pb.InvitationsClient
	events   pb.EventsClient
	key      string
}

var _ Backend = (*Client)(nil)

func New(conn grpc.ClientConnInterface, key string) *Client {
	return &Client{pb.NewSocialClient(conn), pb.NewSessionsClient(conn), pb.NewLinksClient(conn),
		pb.NewInvitationsClient(conn), pb.NewEventsClient(conn), key}
}

func (c *Client) ctx(p context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(p, 3*time.Second)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.key), cancel
}

// mapErr classifies a core error and keeps the real gRPC status in the text
// (errors.Is still matches the class), so logs say what core answered.
func mapErr(err error) error {
	class := ErrUnavailable
	switch status.Code(err) {
	case codes.NotFound:
		class = ErrNotFound
	case codes.InvalidArgument:
		class = ErrInvalid
	case codes.PermissionDenied:
		class = ErrDenied
	case codes.FailedPrecondition, codes.AlreadyExists:
		class = ErrConflict
	}
	return fmt.Errorf("%w (grpc %s: %s)", class, status.Code(err), status.Convert(err).Message())
}

func (c *Client) ListFriends(p context.Context, account string) ([]Friend, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.social.ListFriends(ctx, &pb.ListFriendsRequest{AccountId: account})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Friend, 0, len(r.Friends))
	for _, f := range r.Friends {
		out = append(out, Friend{f.AccountId, f.DisplayName, f.LastSeenUnix, f.FriendsSinceUnix})
	}
	return out, nil
}

func (c *Client) ActiveLink(p context.Context, account string) (Link, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.links.GetActiveLinkByAccount(ctx, &pb.GetActiveLinkByAccountRequest{Namespace: Namespace, AccountId: account})
	if err != nil {
		return Link{}, mapErr(err)
	}
	if r.State != pb.LinkState_LINK_STATE_ACTIVE || r.AccountId != account || r.SubjectId == "" {
		return Link{}, ErrNotFound
	}
	return Link{r.SubjectId, r.PublicCode}, nil
}

func (c *Client) GetPresence(p context.Context, accounts []string) ([]Presence, error) {
	var out []Presence
	for len(accounts) > 0 { // core caps a request at 200 accounts
		n := min(len(accounts), 200)
		ctx, cancel := c.ctx(p)
		r, err := c.sessions.GetPresence(ctx, &pb.GetPresenceRequest{AccountIds: accounts[:n]})
		cancel()
		if err != nil {
			return nil, mapErr(err)
		}
		for _, x := range r.Presence {
			out = append(out, Presence{x.AccountId, x.Namespace, x.TitleId, x.SinceUnix})
		}
		accounts = accounts[n:]
	}
	return out, nil
}

func (c *Client) CanDiscover(p context.Context, actor, target string) (bool, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.social.CheckInteraction(ctx, &pb.CheckInteractionRequest{ActorId: actor, TargetId: target, Kind: pb.InteractionKind_INTERACTION_KIND_DISCOVER})
	if err != nil {
		return false, mapErr(err)
	}
	return r.Allowed, nil
}
