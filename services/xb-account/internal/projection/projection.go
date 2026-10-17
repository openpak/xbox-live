// SPDX-License-Identifier: AGPL-3.0-only

// Package projection gives every active core account an "xbox" link whether or
// not a console was ever enrolled. A console-less account cannot honestly have
// a console identity, so the link carries a placeholder subject that can never
// be a real XUID: real XUIDs are minted as "0009"+12 hex (enrol, provision),
// projection subjects are "0000"+12 hex derived from the account id. The link
// has no public code, no device row and no user row: it admits nobody on the
// console side. A real enrolment replaces it (Release) before it reserves its
// own link, so a projection never blocks, and is never mistaken for, a console.
package projection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strconv"
	"sync"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-account/internal/core"
)

const (
	prefix   = "0000"
	pageSize = 200
	maxGen   = 64
)

// gate serialises "ensure a projection" against "release it and reserve the
// real link", so the reconciler cannot slip a projection in between.
var gate sync.Mutex

// Lock returns the unlock func of the process-wide projection gate.
func Lock() func() { gate.Lock(); return gate.Unlock }

// Is reports whether a link subject is a projection placeholder.
func Is(subject string) bool {
	return len(subject) == 16 && subject[:4] == prefix && xbaccountapi.ValidID(subject)
}

// Subject is the placeholder for an account at a generation. Generation 0 is
// used first; a later one only when core refuses to reuse a retired subject.
func Subject(account string, gen int) string {
	h := sha256.Sum256([]byte("openpak-xbox-projection:" + account + ":" + strconv.Itoa(gen)))
	return prefix + hex.EncodeToString(h[:6])
}

// Release unlinks the account's active projection, if that is what its active
// link is. Callers hold the gate. A real (non-projection) link is left alone.
func Release(ctx context.Context, c core.API, account string) error {
	l, err := c.GetActiveLinkByAccount(ctx, account)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !Is(l.SubjectID) {
		return nil
	}
	return c.UnlinkLink(ctx, l.LinkID, "xbproj:release:"+l.LinkID)
}

// Ensure gives the account an active xbox link if it has none. It reports
// whether it created one. An account with a revoked/unlinked link simply has no
// active link: the old subject is never reused.
func Ensure(ctx context.Context, c core.API, account string) (bool, error) {
	defer Lock()()
	if _, err := c.GetActiveLinkByAccount(ctx, account); err == nil {
		return false, nil
	} else if !errors.Is(err, core.ErrNotFound) {
		return false, err
	}
	for gen := 0; gen < maxGen; gen++ {
		subject := Subject(account, gen)
		idem := "xbproj:" + subject
		id, err := c.ReserveLink(ctx, account, subject, idem)
		if errors.Is(err, core.ErrConflict) || errors.Is(err, core.ErrPrecondition) {
			continue // retired or taken: next generation
		}
		if err != nil {
			return false, err
		}
		err = c.ActivateLink(ctx, id, idem+":activate")
		if errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrNotFound) {
			continue // idempotent replay of a link since revoked
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, core.ErrConflict
}

// Pass walks every active account once. One account failing never stops the
// pass. Counts only; no account data is logged.
func Pass(ctx context.Context, c core.API) (created, failed int, err error) {
	after := ""
	for ctx.Err() == nil {
		ids, next, e := c.ListAccounts(ctx, after, pageSize)
		if e != nil {
			return created, failed, e
		}
		for _, id := range ids {
			if ok, e := Ensure(ctx, c, id); e != nil {
				failed++
			} else if ok {
				created++
			}
		}
		if next == "" || next == after {
			return created, failed, nil
		}
		after = next
	}
	return created, failed, ctx.Err()
}

// Run reconciles at start and then every interval until ctx ends.
func Run(ctx context.Context, c core.API, interval time.Duration) {
	for ctx.Err() == nil {
		created, failed, err := Pass(ctx, c)
		if err != nil {
			log.Printf("xbox projection pass: core unavailable (created=%d failed=%d)", created, failed)
		} else if created > 0 || failed > 0 {
			log.Printf("xbox projection pass: created=%d failed=%d", created, failed)
		}
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}
