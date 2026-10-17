// SPDX-License-Identifier: AGPL-3.0-only

// Package coretest is an in-memory account core for tests. It mirrors the
// semantics xb-social depends on (read from account/internal/{social,sessions,
// invitations}): friendship states, directional blocks, one live session per
// (account, namespace, title) with a 30 s lease that Heartbeat renews to the
// default, invitations bound to a session id with a redelivery window, and a
// versioned event log. It is a test double, not a specification.
package coretest

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"openpak/xb-live/services/xb-social/internal/core"
)

type Link struct {
	Namespace, Subject, Code string
	Active                   bool
}

type session struct {
	id, account, ns, title, ref string
	expires, created            time.Time
}

type invitation struct {
	id, from, to, ns, title, session, nonce string
	payload                                 []byte
	expires                                 time.Time
	state                                   string // pending, delivered, expired, rejected
	redeliverAt                             time.Time
}

type Core struct {
	mu      sync.Mutex
	clock   time.Time
	status  map[string]string // account -> active/banned/deleted
	names   map[string]string
	links   map[string][]Link
	friends map[[2]string]string // {requester, addressee} -> pending/accepted
	blocks  map[[2]string]time.Time
	sess    map[string]*session
	invs    map[string]*invitation
	events  []core.Event
	n       int
	// Fail returns an error to inject for an operation name, or nil.
	Fail func(op string) error
	// Calls records operation names in order.
	Calls []string
}

var _ core.Backend = (*Core)(nil)

func New() *Core {
	return &Core{clock: time.Unix(1_800_000_000, 0), status: map[string]string{}, names: map[string]string{},
		links: map[string][]Link{}, friends: map[[2]string]string{}, blocks: map[[2]string]time.Time{},
		sess: map[string]*session{}, invs: map[string]*invitation{}}
}

// Now is the fake clock; Advance moves it.
func (c *Core) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.clock }
func (c *Core) Advance(d time.Duration) {
	c.mu.Lock()
	c.clock = c.clock.Add(d)
	c.mu.Unlock()
}

func (c *Core) begin(op string) error {
	c.Calls = append(c.Calls, op)
	if c.Fail != nil {
		return c.Fail(op)
	}
	return nil
}

func (c *Core) id(prefix string) string { c.n++; return fmt.Sprintf("%s-%d", prefix, c.n) }

func (c *Core) emit(typ, account, ns, subject string) {
	v := uint64(len(c.events) + 1)
	c.events = append(c.events, core.Event{Version: v, ID: fmt.Sprintf("ev-%d", v), Type: typ, Account: account, Namespace: ns, Subj: subject, Created: c.clock.Unix()})
}

func (c *Core) AddAccount(id, name string) {
	c.mu.Lock()
	c.status[id], c.names[id] = "active", name
	c.mu.Unlock()
}

// LinkXbox gives the account an active xbox link.
func (c *Core) LinkXbox(account, xuid, gamertag string) {
	c.AddLink(account, core.Namespace, xuid, gamertag)
}

func (c *Core) AddLink(account, ns, subject, code string) {
	c.mu.Lock()
	c.links[account] = append(c.links[account], Link{ns, subject, code, true})
	c.mu.Unlock()
}

// Unlink revokes the account's links in ns and emits link_unlinked.
func (c *Core) Unlink(account, ns string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.links[account] {
		if c.links[account][i].Namespace == ns {
			c.links[account][i].Active = false
		}
	}
	c.emit("link_unlinked", account, ns, "")
}

// Ban bans the account: sessions die, an event is emitted.
func (c *Core) Ban(account string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status[account] = "banned"
	for id, s := range c.sess {
		if s.account == account {
			delete(c.sess, id)
		}
	}
	c.emit("account_banned", account, "", "")
}

// Banned reports whether the account was banned.
func (c *Core) Banned(a string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status[a] == "banned"
}

func (c *Core) Sessions(account string) (out []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sess {
		if s.account == account && s.expires.After(c.clock) {
			out = append(out, s.ns+"/"+s.title)
		}
	}
	sort.Strings(out)
	return out
}

func (c *Core) Emit(typ, account, ns, subject string) {
	c.mu.Lock()
	c.emit(typ, account, ns, subject)
	c.mu.Unlock()
}

func (c *Core) rel(a, b string) core.Relationship {
	if _, ok := c.blocks[[2]string{a, b}]; ok {
		return core.RelBlockedBySelf
	}
	if _, ok := c.blocks[[2]string{b, a}]; ok {
		return core.RelBlockedByOther
	}
	if c.friends[[2]string{a, b}] == "accepted" || c.friends[[2]string{b, a}] == "accepted" {
		return core.RelFriends
	}
	if c.friends[[2]string{a, b}] == "pending" {
		return core.RelPendingOutgoing
	}
	if c.friends[[2]string{b, a}] == "pending" {
		return core.RelPendingIncoming
	}
	return core.RelNone
}

func (c *Core) active(a string) bool { return c.status[a] == "active" }

func (c *Core) ListFriends(_ context.Context, a string) ([]core.Friend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ListFriends"); err != nil {
		return nil, err
	}
	var out []core.Friend
	for k, st := range c.friends {
		if st != "accepted" || (k[0] != a && k[1] != a) {
			continue
		}
		o := k[0]
		if o == a {
			o = k[1]
		}
		out = append(out, core.Friend{AccountID: o, DisplayName: c.names[o], Since: c.clock.Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AccountID < out[j].AccountID })
	return out, nil
}

func (c *Core) pending(a string, incoming bool) []core.Friend {
	var out []core.Friend
	for k, st := range c.friends {
		if st != "pending" {
			continue
		}
		if incoming && k[1] == a {
			out = append(out, core.Friend{AccountID: k[0], DisplayName: c.names[k[0]], Since: c.clock.Unix()})
		}
		if !incoming && k[0] == a {
			out = append(out, core.Friend{AccountID: k[1], DisplayName: c.names[k[1]], Since: c.clock.Unix()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AccountID < out[j].AccountID })
	return out
}

func (c *Core) ListIncoming(_ context.Context, a string) ([]core.Friend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ListIncoming"); err != nil {
		return nil, err
	}
	return c.pending(a, true), nil
}

func (c *Core) ListOutgoing(_ context.Context, a string) ([]core.Friend, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ListOutgoing"); err != nil {
		return nil, err
	}
	return c.pending(a, false), nil
}

func (c *Core) ListBlocks(_ context.Context, a string) ([]core.Blocked, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ListBlocks"); err != nil {
		return nil, err
	}
	var out []core.Blocked
	for k, at := range c.blocks {
		if k[0] == a {
			out = append(out, core.Blocked{AccountID: k[1], DisplayName: c.names[k[1]], At: at.Unix()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AccountID < out[j].AccountID })
	return out, nil
}

func (c *Core) ActiveLink(_ context.Context, a string) (core.Link, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ActiveLink"); err != nil {
		return core.Link{}, err
	}
	for _, l := range c.links[a] {
		if l.Namespace == core.Namespace && l.Active {
			return core.Link{SubjectID: l.Subject, PublicCode: l.Code}, nil
		}
	}
	return core.Link{}, core.ErrNotFound
}

func (c *Core) Relationship(_ context.Context, a, b string) (core.Relationship, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("Relationship"); err != nil {
		return 0, err
	}
	return c.rel(a, b), nil
}

func (c *Core) interact(a, t string) bool {
	if a == t || !c.active(a) || !c.active(t) {
		return false
	}
	return c.rel(a, t) == core.RelFriends
}

func (c *Core) CanDiscover(_ context.Context, a, t string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("CanDiscover"); err != nil {
		return false, err
	}
	return c.interact(a, t), nil
}

func (c *Core) CanInvite(_ context.Context, a, t string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("CanInvite"); err != nil {
		return false, err
	}
	return c.interact(a, t), nil
}

func (c *Core) RequestFriend(_ context.Context, from, to, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("RequestFriend"); err != nil {
		return err
	}
	if from == to {
		return core.ErrInvalid
	}
	switch c.rel(from, to) {
	case core.RelFriends, core.RelPendingOutgoing:
		return nil
	case core.RelPendingIncoming, core.RelBlockedBySelf, core.RelBlockedByOther:
		return core.ErrConflict
	}
	c.friends[[2]string{from, to}] = "pending"
	c.emit("friend_requested", to, "", from)
	return nil
}

func (c *Core) AcceptFriend(_ context.Context, addressee, requester, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("AcceptFriend"); err != nil {
		return err
	}
	k := [2]string{requester, addressee}
	switch c.friends[k] {
	case "pending":
		c.friends[k] = "accepted"
		c.emit("friend_accepted", requester, "", addressee)
		return nil
	case "accepted":
		return nil
	}
	return core.ErrConflict
}

func (c *Core) RemoveFriend(_ context.Context, a, o string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("RemoveFriend"); err != nil {
		return err
	}
	removed := false
	for _, k := range [][2]string{{a, o}, {o, a}} {
		if c.friends[k] != "" {
			delete(c.friends, k)
			removed = true
		}
	}
	if removed {
		c.emit("friend_removed", a, "", o)
		c.emit("friend_removed", o, "", a)
	}
	return nil
}

func (c *Core) Block(_ context.Context, blocker, blocked string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("Block"); err != nil {
		return err
	}
	if blocker == blocked {
		return core.ErrInvalid
	}
	if _, ok := c.blocks[[2]string{blocker, blocked}]; !ok {
		c.blocks[[2]string{blocker, blocked}] = c.clock
	}
	return nil
}

func (c *Core) Unblock(_ context.Context, blocker, blocked string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("Unblock"); err != nil {
		return err
	}
	delete(c.blocks, [2]string{blocker, blocked})
	return nil
}

const lease = 30 * time.Second

func (c *Core) RegisterSession(_ context.Context, account, title, ref string, d time.Duration) (string, time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("RegisterSession"); err != nil {
		return "", 0, err
	}
	if !c.active(account) {
		return "", 0, core.ErrNotFound
	}
	if d <= 0 {
		d = lease
	}
	// Unique (account, namespace, title): a new registration replaces the row.
	for id, s := range c.sess {
		if s.account == account && s.ns == core.Namespace && s.title == title {
			delete(c.sess, id)
		}
	}
	id := c.id("sess")
	c.sess[id] = &session{id, account, core.Namespace, title, ref, c.clock.Add(d), c.clock}
	return id, d, nil
}

func (c *Core) Heartbeat(_ context.Context, id string) (time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("Heartbeat"); err != nil {
		return 0, err
	}
	s := c.sess[id]
	if s == nil || !s.expires.After(c.clock) {
		return 0, core.ErrNotFound
	}
	if !c.active(s.account) {
		delete(c.sess, id)
		return 0, core.ErrNotFound
	}
	s.expires = c.clock.Add(lease) // like core: always the default, never longer
	return lease, nil
}

func (c *Core) ExpireSession(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ExpireSession"); err != nil {
		return err
	}
	delete(c.sess, id)
	return nil
}

func (c *Core) GetPresence(_ context.Context, ids []string) ([]core.Presence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("GetPresence"); err != nil {
		return nil, err
	}
	var out []core.Presence
	for _, a := range ids {
		var best *session
		for _, s := range c.sess {
			if s.account != a || !s.expires.After(c.clock) {
				continue
			}
			if best == nil || (s.title != "") && best.title == "" || (s.title != "") == (best.title != "") && s.created.After(best.created) {
				best = s
			}
		}
		if best != nil {
			out = append(out, core.Presence{AccountID: a, Namespace: best.ns, TitleID: best.title, SinceUnix: best.created.Unix()})
		}
	}
	return out, nil
}

// AddForeignSession puts a live session of another namespace in place.
func (c *Core) AddForeignSession(account, ns, title string) {
	c.mu.Lock()
	id := c.id("sess")
	c.sess[id] = &session{id, account, ns, title, "ref", c.clock.Add(time.Hour), c.clock}
	c.mu.Unlock()
}

// LinkOf reads a link without going through the (failure-injected) API.
func (c *Core) LinkOf(account string) (Link, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.links[account] {
		if l.Namespace == core.Namespace && l.Active {
			return l, true
		}
	}
	return Link{}, false
}

func (c *Core) ResolveSession(_ context.Context, account, title string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ResolveSession"); err != nil {
		return "", err
	}
	var best *session
	for _, s := range c.sess {
		if s.account == account && s.title == title && s.expires.After(c.clock) && c.active(account) && (best == nil || s.created.After(best.created)) {
			best = s
		}
	}
	if best == nil {
		return "", core.ErrNotFound
	}
	return best.ns, nil
}

func (c *Core) SendInvitation(_ context.Context, from, to, title string, payload []byte, ttl time.Duration) (string, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("SendInvitation"); err != nil {
		return "", "", err
	}
	if from == to || len(payload) == 0 || len(payload) > 4096 || ttl <= 0 || title == "" {
		return "", "", core.ErrInvalid
	}
	if !c.interact(from, to) {
		return "", "", core.ErrDenied
	}
	var target *session
	for _, s := range c.sess { // like core: any namespace with that title, newest first
		if s.account == to && s.title == title && s.expires.After(c.clock) && (target == nil || s.created.After(target.created)) {
			target = s
		}
	}
	if target == nil {
		return "", "", core.ErrConflict
	}
	i := &invitation{id: c.id("inv"), from: from, to: to, ns: target.ns, title: title, session: target.id,
		nonce: c.id("nonce"), payload: payload, expires: c.clock.Add(ttl), state: "pending"}
	c.invs[i.id] = i
	c.emit("invitation_sent", to, target.ns, i.id)
	return i.id, i.nonce, nil
}

func (c *Core) live(i *invitation) bool {
	s := c.sess[i.session]
	return s != nil && s.expires.After(c.clock) && c.interact(i.from, i.to)
}

func (c *Core) PollInvitations(_ context.Context, account string, limit int) ([]core.Invitation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("PollInvitations"); err != nil {
		return nil, err
	}
	var out []core.Invitation
	ids := make([]string, 0, len(c.invs))
	for id := range c.invs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		i := c.invs[id]
		if i.to != account || i.ns != core.Namespace || i.state != "pending" || (limit > 0 && len(out) >= limit) {
			continue
		}
		if !i.expires.After(c.clock) || !c.live(i) {
			i.state = "expired"
			continue
		}
		if c.clock.Before(i.redeliverAt) {
			continue
		}
		i.redeliverAt = c.clock.Add(60 * time.Second)
		out = append(out, core.Invitation{ID: i.id, From: i.from, FromName: c.names[i.from], TitleID: i.title, Payload: i.payload, Nonce: i.nonce, Expires: i.expires.Unix()})
	}
	return out, nil
}

func (c *Core) AckInvitations(_ context.Context, account string, ids, nonces []string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("AckInvitations"); err != nil {
		return 0, err
	}
	n := 0
	for k, id := range ids {
		i := c.invs[id]
		if i != nil && i.to == account && i.state == "pending" && k < len(nonces) && nonces[k] == i.nonce {
			i.state = "delivered"
			n++
		}
	}
	return n, nil
}

func (c *Core) ListInvitations(_ context.Context, account string, limit int) ([]core.InvitationSummary, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("ListInvitations"); err != nil {
		return nil, err
	}
	var out []core.InvitationSummary
	for _, i := range c.invs {
		if i.to == account && i.state == "pending" && i.expires.After(c.clock) {
			out = append(out, core.InvitationSummary{ID: i.id, From: i.from, FromName: c.names[i.from], TitleID: i.title, Namespace: i.ns, Expires: i.expires.Unix()})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

func (c *Core) RejectInvitation(_ context.Context, account, id string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("RejectInvitation"); err != nil {
		return false, err
	}
	i := c.invs[id]
	if i == nil || i.to != account || i.state != "pending" {
		return false, nil
	}
	i.state = "rejected"
	return true, nil
}

func (c *Core) PollEvents(_ context.Context, since uint64, limit int) ([]core.Event, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.begin("PollEvents"); err != nil {
		return nil, 0, err
	}
	var out []core.Event
	for _, e := range c.events {
		if e.Version > since && (limit <= 0 || len(out) < limit) {
			out = append(out, e)
		}
	}
	return out, uint64(len(c.events)), nil
}
