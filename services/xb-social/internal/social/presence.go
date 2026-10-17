// SPDX-License-Identifier: AGPL-3.0-only

package social

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"openpak/xb-live/services/xb-social/internal/core"
)

// DashboardTitle is the title id the dashboard reports (Xombie alive2 vector).
const DashboardTitle = 0xfffe0000

// Presence TTL bounds. Core caps a lease at 300 s and a Heartbeat always
// renews to its own 30 s default, so the console's Alive extends a logical
// deadline here and Tick keeps the core lease alive until that deadline.
const (
	DefaultTTL = 120 * time.Second
	MinTTL     = 15 * time.Second
	MaxTTL     = 10 * time.Minute
)

// TitleKey formats a native title id the way the core stores it: 8 lowercase
// hex digits. Title 0 and 0xFFFE0000 (the dashboard) are signed-in-but-not-in-a-title,
// which core represents as the empty title.
func TitleKey(id uint32) string {
	if id == 0 || id == DashboardTitle {
		return ""
	}
	return fmt.Sprintf("%08x", id)
}

// Presences publishes Xbox presence as core Sessions leases in namespace
// "xbox". Semantics, all against core's rules:
//
//   - core allows one live session per (account, namespace, title). A title
//     change registers the new title and then expires the old session, so the
//     user never flickers offline and no stale title lingers.
//   - re-registering replaces the session id and would orphan invitations bound
//     to it, so a repeat Publish for the same title only moves the logical
//     deadline; Tick heartbeats the existing session.
//   - the newest connection generation owns the account. An older generation is
//     refused (ErrSuperseded) and cannot expire or take back the session.
//   - disconnect or sign-out expires the session at once (by its own id, so it
//     can never remove a successor's); otherwise it lapses at the deadline.
type Presences struct {
	Core core.Backend
	Now  func() time.Time

	mu     sync.Mutex
	leases map[string]*lease
}

type lease struct {
	mu       sync.Mutex // serialises core calls for this account
	gen      uint64
	xuid     string
	title    string
	session  string
	deadline time.Time
	gone     bool
}

func (m *Presences) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func clampTTL(ttl time.Duration) time.Duration {
	switch {
	case ttl <= 0:
		return DefaultTTL
	case ttl < MinTTL:
		return MinTTL
	case ttl > MaxTTL:
		return MaxTTL
	}
	return ttl
}

func (m *Presences) get(account string, create bool) *lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leases == nil {
		m.leases = map[string]*lease{}
	}
	l := m.leases[account]
	if l == nil && create {
		l = &lease{}
		m.leases[account] = l
	}
	return l
}

// Publish records that account (XUID xuid) is online in title (TitleKey) until
// now+ttl, creating, renewing or moving its core session as needed. gen is the
// gateway's connection generation.
func (m *Presences) Publish(ctx context.Context, account, xuid, title string, gen uint64, ttl time.Duration) error {
	for {
		l := m.get(account, true)
		l.mu.Lock()
		if l.gone { // removed while we waited: start over with a fresh entry
			l.mu.Unlock()
			continue
		}
		defer l.mu.Unlock()
		if l.session != "" && gen < l.gen {
			return ErrSuperseded
		}
		return m.publish(ctx, l, account, xuid, title, gen, clampTTL(ttl))
	}
}

func (m *Presences) publish(ctx context.Context, l *lease, account, xuid, title string, gen uint64, ttl time.Duration) error {
	deadline := m.now().Add(ttl)
	if l.session != "" && l.title == title {
		if _, err := m.Core.Heartbeat(ctx, l.session); err == nil {
			l.gen, l.xuid, l.deadline = gen, xuid, maxTime(l.deadline, deadline)
			return nil
		} else if !errors.Is(err, core.ErrNotFound) {
			log.Printf("presence: heartbeat failed, registering again: %v", err)
		}
		// the session lapsed, was replaced elsewhere, or core could not renew it:
		// register again (it replaces whatever live row exists for this title)
	}
	old := l.session
	id, _, err := m.Core.RegisterSession(ctx, account, title, "xbox:"+xuid, 0)
	switch {
	case err == nil:
	default:
		// Includes NotFound (core's answer for an inactive account): the caller
		// has already been admitted by the resolver, so this is not a refusal.
		return fmt.Errorf("%w: register session: %v", ErrUnavailable, err)
	}
	l.session, l.title, l.gen, l.xuid, l.deadline = id, title, gen, xuid, deadline
	if old != "" && old != id {
		// Best effort: a failure only leaves the old title until its 30 s lease ends.
		if err := m.Core.ExpireSession(ctx, old); err != nil && !errors.Is(err, core.ErrNotFound) && !errors.Is(err, core.ErrConflict) {
			log.Printf("presence: expire old session failed (ignored): %v", err)
		}
	}
	return nil
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Disconnect ends presence because the connection of generation gen closed. A
// newer generation keeps the session.
func (m *Presences) Disconnect(ctx context.Context, account string, gen uint64) error {
	return m.end(ctx, account, func(l *lease) bool { return gen >= l.gen })
}

// Touch extends the logical deadline of the account's session while the gateway
// reports its connection (generation gen) alive; a console sends one Alive per
// sign-in and no periodic one. Other generations and unknown accounts are ignored.
func (m *Presences) Touch(account string, gen uint64, ttl time.Duration) {
	l := m.get(account, false)
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.gone && l.session != "" && l.gen == gen {
		l.deadline = maxTime(l.deadline, m.now().Add(clampTTL(ttl)))
	}
}

// Revoke ends presence unconditionally (ban, unlink, deletion).
func (m *Presences) Revoke(ctx context.Context, account string) error {
	return m.end(ctx, account, func(*lease) bool { return true })
}

func (m *Presences) end(ctx context.Context, account string, ok func(*lease) bool) error {
	l := m.get(account, false)
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gone || !ok(l) {
		return nil
	}
	log.Printf("presence: ending %s (gen %d)", account, l.gen)
	if l.session != "" {
		if err := m.Core.ExpireSession(ctx, l.session); err != nil && !errors.Is(err, core.ErrNotFound) {
			return ErrUnavailable // keep the entry: the next Tick or Revoke retries
		}
	}
	l.gone = true
	m.mu.Lock()
	if m.leases[account] == l {
		delete(m.leases, account)
	}
	m.mu.Unlock()
	return nil
}

// Current reports the title the account is published in (ok false when not online).
func (m *Presences) Current(account string) (title string, ok bool) {
	l := m.get(account, false)
	if l == nil {
		return "", false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gone || l.session == "" || !m.now().Before(l.deadline) {
		return "", false
	}
	return l.title, true
}

// XUIDOf returns the XUID the account is currently online as.
func (m *Presences) XUIDOf(account string) (string, bool) {
	l := m.get(account, false)
	if l == nil {
		return "", false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gone || l.session == "" || !m.now().Before(l.deadline) {
		return "", false
	}
	return l.xuid, true
}

// Tick renews core leases of accounts still inside their deadline and expires
// the rest. Run it every ~10 s (core's lease is 30 s).
func (m *Presences) Tick(ctx context.Context) {
	m.mu.Lock()
	accounts := make([]string, 0, len(m.leases))
	for a := range m.leases {
		accounts = append(accounts, a)
	}
	m.mu.Unlock()
	for _, a := range accounts {
		l := m.get(a, false)
		if l == nil {
			continue
		}
		l.mu.Lock()
		if l.gone {
			l.mu.Unlock()
			continue
		}
		expired := !m.now().Before(l.deadline)
		if expired {
			log.Printf("presence: lease of %s expired by TTL (deadline %s, gen %d)", a, l.deadline.Format("15:04:05"), l.gen)
		}
		if !expired {
			if _, err := m.Core.Heartbeat(ctx, l.session); errors.Is(err, core.ErrNotFound) {
				log.Printf("presence: core lease of %s lapsed; registering %q again", a, l.title)
				// Lease lost (core expired it): register the same title again.
				if id, _, err := m.Core.RegisterSession(ctx, a, l.title, "xbox:"+l.xuid, 0); err == nil {
					l.session = id
				}
			}
			l.mu.Unlock()
			continue
		}
		l.mu.Unlock()
		_ = m.end(ctx, a, func(l *lease) bool { return !m.now().Before(l.deadline) })
	}
}

// Run calls Tick every interval until ctx ends.
func (m *Presences) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Tick(ctx)
		}
	}
}
