// SPDX-License-Identifier: AGPL-3.0-only
// Package core wraps the account-core gRPC contracts xb-account needs, mapping
// transport errors to a small closed set. It never reads core tables.
package core

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
)

// Namespace is the account-core link namespace for native Xbox identities.
// It is deliberately "xbox", never "xbl".
const Namespace = "xbox"

var (
	ErrNotFound     = errors.New("core: not found")
	ErrConflict     = errors.New("core: conflict")
	ErrPrecondition = errors.New("core: failed precondition")
	ErrInvalid      = errors.New("core: invalid request")
	ErrUnavailable  = errors.New("core: unavailable")
)

type Account struct {
	ID     string
	Status pb.AccountStatus
	Name   string
}

type Link struct {
	LinkID, AccountID, SubjectID, PublicCode string
	State                                    pb.LinkState
}

type Event struct {
	Version                                   uint64
	ID, Type, AccountID, Namespace, SubjectID string
	CreatedUnix                               int64
}

// API is the subset of core used by provisioning, resolution and revocation.
type API interface {
	GetAccount(ctx context.Context, id string) (Account, error)
	GetLinkBySubject(ctx context.Context, subject string) (Link, error)
	GetActiveLinkByAccount(ctx context.Context, account string) (Link, error)
	ReserveLink(ctx context.Context, account, subject, idem string) (linkID string, err error)
	ActivateLink(ctx context.Context, linkID, idem string) error
	UnlinkLink(ctx context.Context, linkID, idem string) error
	SetLinkPublicCode(ctx context.Context, linkID, code string) error
	PollEvents(ctx context.Context, since uint64, limit int) ([]Event, error)
	// ListAccounts pages active accounts by keyset (after = last id of the previous page; next "" at the end).
	ListAccounts(ctx context.Context, after string, limit int) (ids []string, next string, err error)
}

type Client struct {
	links    pb.LinksClient
	identity pb.IdentityClient
	events   pb.EventsClient
	key      string
}

func New(conn grpc.ClientConnInterface, key string) *Client {
	return &Client{pb.NewLinksClient(conn), pb.NewIdentityClient(conn), pb.NewEventsClient(conn), key}
}

func (c *Client) ctx(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.key), cancel
}

func mapErr(err error) error {
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.NotFound:
		return ErrNotFound
	case codes.AlreadyExists:
		return ErrConflict
	case codes.FailedPrecondition:
		return ErrPrecondition
	case codes.InvalidArgument:
		return ErrInvalid
	default:
		return ErrUnavailable
	}
}

func (c *Client) GetAccount(p context.Context, id string) (Account, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.identity.GetAccount(ctx, &pb.GetAccountRequest{AccountId: id})
	if err != nil {
		return Account{}, mapErr(err)
	}
	if r.AccountId != id {
		return Account{}, ErrUnavailable
	}
	return Account{r.AccountId, r.Status, r.DisplayName}, nil
}

func link(r *pb.GetLinkBySubjectResponse, subject string) Link {
	s := r.SubjectId
	if s == "" {
		s = subject
	}
	return Link{r.LinkId, r.AccountId, s, r.PublicCode, r.State}
}

func (c *Client) GetLinkBySubject(p context.Context, subject string) (Link, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.links.GetLinkBySubject(ctx, &pb.GetLinkBySubjectRequest{Namespace: Namespace, SubjectId: subject})
	if err != nil {
		return Link{}, mapErr(err)
	}
	return link(r, subject), nil
}

func (c *Client) GetActiveLinkByAccount(p context.Context, account string) (Link, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.links.GetActiveLinkByAccount(ctx, &pb.GetActiveLinkByAccountRequest{Namespace: Namespace, AccountId: account})
	if err != nil {
		return Link{}, mapErr(err)
	}
	return link(r, ""), nil
}

func (c *Client) ReserveLink(p context.Context, account, subject, idem string) (string, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.links.ReserveLink(ctx, &pb.ReserveLinkRequest{AccountId: account, Namespace: Namespace, SubjectId: subject, IdempotencyKey: idem})
	if err != nil {
		return "", mapErr(err)
	}
	if r.LinkId == "" {
		return "", ErrUnavailable
	}
	return r.LinkId, nil
}

func (c *Client) ActivateLink(p context.Context, linkID, idem string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.links.ActivateLink(ctx, &pb.ActivateLinkRequest{LinkId: linkID, IdempotencyKey: idem})
	return mapErr(err)
}

func (c *Client) UnlinkLink(p context.Context, linkID, idem string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.links.UnlinkLink(ctx, &pb.UnlinkLinkRequest{LinkId: linkID, IdempotencyKey: idem})
	if err = mapErr(err); errors.Is(err, ErrNotFound) {
		return nil // already gone
	}
	return err
}

func (c *Client) SetLinkPublicCode(p context.Context, linkID, code string) error {
	ctx, cancel := c.ctx(p)
	defer cancel()
	_, err := c.links.SetLinkPublicCode(ctx, &pb.SetLinkPublicCodeRequest{LinkId: linkID, PublicCode: code})
	return mapErr(err)
}

func (c *Client) PollEvents(p context.Context, since uint64, limit int) ([]Event, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.events.PollEvents(ctx, &pb.PollEventsRequest{SinceVersion: since, Limit: int32(limit)})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Event, 0, len(r.Events))
	for _, e := range r.Events {
		out = append(out, Event{e.Version, e.EventId, e.Type, e.AccountId, e.Namespace, e.SubjectId, e.CreatedAtUnix})
	}
	return out, nil
}

func (c *Client) ListAccounts(p context.Context, after string, limit int) ([]string, string, error) {
	ctx, cancel := c.ctx(p)
	defer cancel()
	r, err := c.identity.ListAccounts(ctx, &pb.ListAccountsRequest{AfterAccountId: after, Limit: int32(limit)})
	if err != nil {
		return nil, "", mapErr(err)
	}
	ids := make([]string, 0, len(r.Accounts))
	for _, a := range r.Accounts {
		ids = append(ids, a.AccountId)
	}
	return ids, r.NextAfterAccountId, nil
}
