// SPDX-License-Identifier: AGPL-3.0-only

package social

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"openpak/xb-live/services/xb-social/internal/core"
)

// NoticeKind is what changed for an account.
type NoticeKind string

const (
	NoticeFriendRequested NoticeKind = "friend_requested" // Subject asked Account
	NoticeFriendAccepted  NoticeKind = "friend_accepted"
	NoticeFriendRemoved   NoticeKind = "friend_removed"
	NoticeInvitation      NoticeKind = "invitation"       // Subject is the invitation id
	NoticePresence        NoticeKind = "presence_changed" // Subject's presence moved
	NoticeRevoked         NoticeKind = "revoked"          // ban, unlink or deletion: drop the connection
	NoticeAnswer          NoticeKind = "invite_answer"    // Subject answered an invitation Account sent
)

// Notice is a hint that state changed; the truth is always re-read from core
// (Roster, PollInvites). Account and Subject are core account ids.
type Notice struct {
	Kind    NoticeKind
	Account string
	Subject string
	EventID string
}

// Hub fans notices out to the live connections of an account. Delivery is
// best effort: a slow subscriber loses its oldest notices (it re-reads the
// roster, which is authoritative) and is told through Lost.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[*Subscription]struct{}
	taps []func(Notice)
}

// Tap registers fn to see every notice (called synchronously: it must not block).
func (h *Hub) Tap(fn func(Notice)) {
	h.mu.Lock()
	h.taps = append(h.taps, fn)
	h.mu.Unlock()
}

type Subscription struct {
	C    chan Notice
	lost bool
	hub  *Hub
	acct string
}

// Lost reports (and clears) whether notices were dropped; a true answer means
// the subscriber must resynchronise from core.
func (s *Subscription) Lost() bool {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	l := s.lost
	s.lost = false
	return l
}

func (s *Subscription) Close() {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	delete(s.hub.subs[s.acct], s)
	if len(s.hub.subs[s.acct]) == 0 {
		delete(s.hub.subs, s.acct)
	}
}

func (h *Hub) Subscribe(account string) *Subscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subs == nil {
		h.subs = map[string]map[*Subscription]struct{}{}
	}
	s := &Subscription{C: make(chan Notice, 16), hub: h, acct: account}
	if h.subs[account] == nil {
		h.subs[account] = map[*Subscription]struct{}{}
	}
	h.subs[account][s] = struct{}{}
	return s
}

func (h *Hub) Publish(n Notice) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, fn := range h.taps {
		fn(n)
	}
	for s := range h.subs[n.Account] {
		for {
			select {
			case s.C <- n:
			default:
				select { // full: drop the oldest, remember that we did
				case <-s.C:
					s.lost = true
					continue
				default:
				}
			}
			break
		}
	}
}

// CursorStore persists the last fully handled core event version.
type CursorStore interface {
	// Load returns ErrNoCursor when nothing was ever saved.
	Load() (uint64, error)
	Save(version uint64) error
}

var ErrNoCursor = errors.New("social: no cursor saved")

// MemCursor is an in-memory CursorStore (tests).
type MemCursor struct {
	mu  sync.Mutex
	v   uint64
	set bool
}

func (c *MemCursor) Load() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.set {
		return 0, ErrNoCursor
	}
	return c.v, nil
}

func (c *MemCursor) Save(v uint64) error {
	c.mu.Lock()
	c.v, c.set = v, true
	c.mu.Unlock()
	return nil
}

// FileCursor stores the version in a file, replaced atomically.
type FileCursor struct{ Path string }

func (c FileCursor) Load() (uint64, error) {
	b, err := os.ReadFile(c.Path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNoCursor
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

func (c FileCursor) Save(v uint64) error {
	tmp, err := os.CreateTemp(filepath.Dir(c.Path), ".cursor-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(strconv.FormatUint(v, 10) + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.Path)
}

// Poller reads core's durable event stream from a persisted cursor, handles
// each event once (deduplicated by event id, since delivery is at-least-once
// and the cursor is only saved after a page), and applies the effects:
// revocations end presence, the rest become Hub notices.
//
// An effect that fails stops the page before the failing event and the cursor
// stays behind it, so the event is retried; effects are idempotent.
type Poller struct {
	Core     core.Backend
	Cursor   CursorStore
	Hub      *Hub
	Presence *Presences // nil: revocations only notify
	PageSize int
	Interval time.Duration

	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
}

const seenMax = 4096

func (p *Poller) dup(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[id]; ok {
		return true
	}
	return false
}

func (p *Poller) mark(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string]struct{}{}
	}
	p.seen[id] = struct{}{}
	p.order = append(p.order, id)
	if len(p.order) > seenMax {
		delete(p.seen, p.order[0])
		p.order = p.order[1:]
	}
}

// Step handles one page and returns how many events it handled.
func (p *Poller) Step(ctx context.Context) (int, error) {
	since, err := p.Cursor.Load()
	if errors.Is(err, ErrNoCursor) {
		// First start: nothing before now needs pushing (state is re-read from
		// core on demand), so begin at the stream's head.
		_, max, err := p.Core.PollEvents(ctx, 0, 1)
		if err != nil {
			return 0, err
		}
		return 0, p.Cursor.Save(max)
	}
	if err != nil {
		return 0, err
	}
	size := p.PageSize
	if size <= 0 {
		size = 200
	}
	evs, max, err := p.Core.PollEvents(ctx, since, size)
	if err != nil {
		return 0, err
	}
	n := 0
	last := since
	for _, e := range evs {
		if e.Version <= since {
			continue
		}
		if !p.dup(e.ID) {
			if err := p.apply(ctx, e); err != nil {
				if last > since {
					_ = p.Cursor.Save(last)
				}
				return n, err
			}
			p.mark(e.ID)
			n++
		}
		last = e.Version
	}
	if len(evs) == 0 && max > last {
		last = max // nothing relevant in range: skip ahead
	}
	if last > since {
		if err := p.Cursor.Save(last); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (p *Poller) apply(ctx context.Context, e core.Event) error {
	var kind NoticeKind
	switch e.Type {
	case "friend_requested", "friend_accepted", "friend_removed":
		kind = NoticeKind(e.Type)
	case "invitation_sent":
		if e.Namespace != core.Namespace {
			return nil
		}
		kind = NoticeInvitation
	case "presence_changed":
		kind = NoticePresence
	case "account_banned", "account_delete_started", "account_deleted":
		kind = NoticeRevoked
	case "link_unlinked":
		if e.Namespace != core.Namespace {
			return nil // a Switch or Wii U unlink is not ours
		}
		kind = NoticeRevoked
	default:
		return nil
	}
	if e.Account == "" {
		return nil
	}
	if kind == NoticeRevoked && p.Presence != nil {
		if err := p.Presence.Revoke(ctx, e.Account); err != nil {
			return err
		}
	}
	if p.Hub != nil {
		p.Hub.Publish(Notice{Kind: kind, Account: e.Account, Subject: e.Subj, EventID: e.ID})
	}
	return nil
}

// Run polls until ctx ends, backing off on errors.
func (p *Poller) Run(ctx context.Context) {
	iv := p.Interval
	if iv <= 0 {
		iv = 2 * time.Second
	}
	back := iv
	for {
		n, err := p.Step(ctx)
		wait := iv
		switch {
		case err != nil:
			log.Printf("events: poll failed: %v", err)
			back = min(back*2, 30*time.Second)
			wait = back
		case n > 0:
			back, wait = iv, 0 // more may be waiting
		default:
			back = iv
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
