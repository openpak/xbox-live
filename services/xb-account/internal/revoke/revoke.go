// SPDX-License-Identifier: AGPL-3.0-only

// Package revoke consumes the account-core event stream with a durable cursor
// and turns relevant events (ban, unban, unlink, deletion, credential
// revocation) into local status changes plus entries on the Revocations
// stream. Processing is idempotent: each event applies its effect and moves
// the cursor in one transaction, and a redelivered event_id is a no-op.
package revoke

import (
	"context"
	"errors"
	"log"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-account/internal/core"
	"openpak/xb-live/services/xb-account/internal/store"
)

type Processor struct {
	Core  core.API
	Store *store.Store
	Batch int
}

var (
	live     = []xbaccountapi.Status{xbaccountapi.StatusActive, xbaccountapi.StatusBanned}
	anything = []xbaccountapi.Status{xbaccountapi.StatusActive, xbaccountapi.StatusBanned, xbaccountapi.StatusUnlinked, xbaccountapi.StatusRevoked}
)

// Plan maps one core event to its local change. Unknown or foreign events
// yield a change that only advances the cursor.
func Plan(e core.Event) store.Change {
	c := store.Change{EventID: e.ID, Version: e.Version, AccountID: e.AccountID}
	acct := func(r xbaccountapi.Status) *xbaccountapi.Revocation {
		return &xbaccountapi.Revocation{Scope: xbaccountapi.ScopeAccount, CoreAccountID: e.AccountID, Reason: r}
	}
	if e.AccountID == "" {
		return c
	}
	switch e.Type {
	case "account_banned":
		c.SetAccount = &store.StatusChange{From: []xbaccountapi.Status{xbaccountapi.StatusActive}, To: xbaccountapi.StatusBanned, Users: true, Devices: true}
		c.Emit = acct(xbaccountapi.StatusBanned)
	case "account_unbanned":
		c.SetAccount = &store.StatusChange{From: []xbaccountapi.Status{xbaccountapi.StatusBanned}, To: xbaccountapi.StatusActive, Users: true, Devices: true}
	case "link_unlinked":
		if e.Namespace == core.Namespace && xbaccountapi.ValidID(e.SubjectID) {
			c.UnlinkXUID = e.SubjectID
			c.Emit = &xbaccountapi.Revocation{Scope: xbaccountapi.ScopeUser, PrincipalID: e.SubjectID, CoreAccountID: e.AccountID, Reason: xbaccountapi.StatusUnlinked}
		}
	case "account_delete_started", "account_deleted":
		c.SetAccount = &store.StatusChange{From: anything, To: xbaccountapi.StatusDeleted, Users: true, Devices: true, ReleaseGamertag: true}
		c.Emit = acct(xbaccountapi.StatusDeleted)
	case "credential_revoked":
		if e.Namespace == "" || e.Namespace == core.Namespace {
			c.SetAccount = &store.StatusChange{From: live, To: xbaccountapi.StatusRevoked, Devices: true}
			c.Emit = acct(xbaccountapi.StatusRevoked)
		}
	}
	return c
}

// ProcessOnce polls one batch after the durable cursor and applies it in
// order. It returns the number of events applied. Events at or below the
// cursor, or out of order within a batch, are skipped, never applied twice.
func (p *Processor) ProcessOnce(ctx context.Context) (int, error) {
	cursor, err := p.Store.Cursor(ctx)
	if err != nil {
		return 0, err
	}
	batch := p.Batch
	if batch <= 0 {
		batch = 200
	}
	events, err := p.Core.PollEvents(ctx, cursor, batch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range events {
		if e.Version <= cursor {
			continue
		}
		if e.ID == "" {
			return n, errors.New("revoke: event without id")
		}
		if err := p.Store.ApplyChange(ctx, Plan(e)); err != nil {
			return n, err
		}
		cursor = e.Version
		n++
	}
	return n, nil
}

// Run polls until ctx ends, draining full batches immediately and otherwise
// waiting interval. Errors are logged without event content and retried.
func (p *Processor) Run(ctx context.Context, interval time.Duration) {
	for ctx.Err() == nil {
		n, err := p.ProcessOnce(ctx)
		if err != nil {
			log.Printf("revocation processor: %v", err)
		}
		if err == nil && n > 0 {
			continue
		}
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}
