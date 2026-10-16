// SPDX-License-Identifier: AGPL-3.0-only

// Package core is xb-social's read-only view of account core: the canonical
// friend graph (Social), live presence (Sessions) and adapter links (Links).
// xb-social never writes the graph and never keeps its own copy of it.
package core

import (
	"context"
	"errors"
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
	key      string
}

func New(conn grpc.ClientConnInterface, key string) *Client {
	return &Client{pb.NewSocialClient(conn), pb.NewSessionsClient(conn), pb.NewLinksClient(conn), key}
}

func (c *Client) ctx(p context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(p, 3*time.Second)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.key), cancel
}

func mapErr(err error) error {
	if status.Code(err) == codes.NotFound {
		return ErrNotFound
	}
	return ErrUnavailable
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
