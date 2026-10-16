// SPDX-License-Identifier: AGPL-3.0-only

// Package coretest is an in-memory account core for tests: it implements
// core.API with the semantics xb-account relies on (idempotent reserve,
// unique public codes, active-link lookups, an event log) plus failure injection.
package coretest

import (
	"context"
	"strings"
	"sync"

	"openpak/xb-live/services/xb-account/internal/core"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
)

type link struct {
	id, account, subject, code string
	state                      pb.LinkState
}

type Core struct {
	mu       sync.Mutex
	Accounts map[string]pb.AccountStatus
	links    map[string]*link
	idem     map[string]string
	events   []core.Event
	n        int
	// Fail returns an error to inject for an operation name, or nil.
	Fail func(op string) error
	Ops  []string
}

var _ core.API = (*Core)(nil)

func New() *Core {
	return &Core{Accounts: map[string]pb.AccountStatus{}, links: map[string]*link{}, idem: map[string]string{}}
}

func (c *Core) begin(op string) error {
	c.Ops = append(c.Ops, op)
	if c.Fail != nil {
		return c.Fail(op)
	}
	return nil
}

func (c *Core) AddAccount(id string, st pb.AccountStatus) {
	c.mu.Lock()
	c.Accounts[id] = st
	c.mu.Unlock()
}

// Emit appends a core event with the next version and returns it.
func (c *Core) Emit(typ, account, ns, subject string) core.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := core.Event{Version: uint64(len(c.events) + 1), ID: "ev-" + typ + "-" + string(rune('a'+len(c.events))), Type: typ, AccountID: account, Namespace: ns, SubjectID: subject}
	c.events = append(c.events, e)
	return e
}

// Redeliver appends a copy of e (same ID) under a new version.
func (c *Core) Redeliver(e core.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.Version = uint64(len(c.events) + 1)
	c.events = append(c.events, e)
}

func (c *Core) State(linkID string) (pb.LinkState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.links[linkID]
	if !ok {
		return 0, false
	}
	return l.state, true
}

func (c *Core) CountOps(op string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, o := range c.Ops {
		if o == op {
			n++
		}
	}
	return n
}

func (c *Core) GetAccount(_ context.Context, id string) (core.Account, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("GetAccount"); err != nil {
		return core.Account{}, err
	}
	st, ok := c.Accounts[id]
	if !ok {
		return core.Account{}, core.ErrNotFound
	}
	return core.Account{ID: id, Status: st, Name: "name-" + id}, nil
}

func (c *Core) toLink(l *link) core.Link {
	return core.Link{LinkID: l.id, AccountID: l.account, SubjectID: l.subject, PublicCode: l.code, State: l.state}
}

func (c *Core) GetLinkBySubject(_ context.Context, subject string) (core.Link, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("GetLinkBySubject"); err != nil {
		return core.Link{}, err
	}
	for _, l := range c.links {
		if l.subject == subject && (l.state == pb.LinkState_LINK_STATE_ACTIVE || l.state == pb.LinkState_LINK_STATE_PENDING) {
			return c.toLink(l), nil
		}
	}
	return core.Link{}, core.ErrNotFound
}

func (c *Core) GetActiveLinkByAccount(_ context.Context, account string) (core.Link, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("GetActiveLinkByAccount"); err != nil {
		return core.Link{}, err
	}
	for _, l := range c.links {
		if l.account == account && l.state == pb.LinkState_LINK_STATE_ACTIVE {
			return c.toLink(l), nil
		}
	}
	return core.Link{}, core.ErrNotFound
}

func (c *Core) ReserveLink(_ context.Context, account, subject, idem string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ReserveLink"); err != nil {
		return "", err
	}
	if id, ok := c.idem[idem]; ok {
		return id, nil
	}
	for _, l := range c.links {
		if l.subject == subject && l.state != pb.LinkState_LINK_STATE_REVOKED {
			return "", core.ErrConflict
		}
	}
	c.n++
	id := "link-" + string(rune('0'+c.n))
	c.links[id] = &link{id: id, account: account, subject: subject, state: pb.LinkState_LINK_STATE_PENDING}
	c.idem[idem] = id
	return id, nil
}

func (c *Core) ActivateLink(_ context.Context, id, idem string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ActivateLink"); err != nil {
		return err
	}
	l, ok := c.links[id]
	if !ok {
		return core.ErrNotFound
	}
	if l.state == pb.LinkState_LINK_STATE_ACTIVE && c.idem[idem] == id {
		return nil
	}
	if l.state != pb.LinkState_LINK_STATE_PENDING {
		return core.ErrPrecondition
	}
	l.state = pb.LinkState_LINK_STATE_ACTIVE
	c.idem[idem] = id
	return nil
}

func (c *Core) UnlinkLink(_ context.Context, id, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("UnlinkLink"); err != nil {
		return err
	}
	if l, ok := c.links[id]; ok {
		l.state, l.code = pb.LinkState_LINK_STATE_REVOKED, ""
	}
	return nil
}

func (c *Core) SetLinkPublicCode(_ context.Context, id, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("SetLinkPublicCode"); err != nil {
		return err
	}
	l, ok := c.links[id]
	if !ok {
		return core.ErrNotFound
	}
	if l.state != pb.LinkState_LINK_STATE_ACTIVE {
		return core.ErrPrecondition
	}
	for _, o := range c.links {
		if o.id != id && o.state == pb.LinkState_LINK_STATE_ACTIVE && strings.EqualFold(o.code, code) {
			return core.ErrConflict
		}
	}
	l.code = code
	return nil
}

func (c *Core) PollEvents(_ context.Context, since uint64, limit int) ([]core.Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("PollEvents"); err != nil {
		return nil, err
	}
	var out []core.Event
	for _, e := range c.events {
		if e.Version > since && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

// Link returns the link with this ID for assertions.
func (c *Core) Link(id string) (core.Link, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.links[id]
	if !ok {
		return core.Link{}, false
	}
	return c.toLink(l), true
}

// SetLinkState forces a link state (simulates an out-of-band unlink).
func (c *Core) SetLinkState(id string, st pb.LinkState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.links[id].state = st
}
