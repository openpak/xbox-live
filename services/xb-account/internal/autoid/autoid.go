// SPDX-License-Identifier: AGPL-3.0-only

// Package autoid gives every active OpenPak account an Xbox identity (xuid,
// unique gamertag, active xbox link, xb-account rows) without a console step.
//
// An automatic identity carries NO credentials: no device row, no proof
// material, no Kerberos key. It can be friended and shown in friend lists, but
// nobody can sign in as it. A real enrolment (provision / enrol) retires it and
// issues the real identity (Release), the same way it replaces the console-less
// projection link. Banned and deleted accounts get none; status changes reach
// the rows through the existing revoke processor.
//
// Allocation is deterministic and idempotent: the xuid is "0009" + 48 bits of
// SHA-256 over the core account id and a generation counter, so a crash and
// retry reserves the same subject with the same idempotency key. A subject
// core refuses (taken or retired) moves to the next generation.
package autoid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	pb "openpak/xb-live/services/xb-account/internal/corepb"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-account/internal/core"
	"openpak/xb-live/services/xb-account/internal/projection"
	"openpak/xb-live/services/xb-account/internal/store"
)

const maxGen = 32

// XUID is the deterministic xuid of an account at a generation.
func XUID(account string, gen int) string {
	h := sha256.Sum256([]byte("openpak-xbox-auto-xuid:" + account + ":" + strconv.Itoa(gen)))
	return "0009" + hex.EncodeToString(h[:6])
}

// Gamertag derives a console gamertag (<= 15 chars, letters, digits and inner
// single spaces) from a display name. attempt > 0 appends a digit suffix that
// is stable for (name, account, attempt) so retries converge.
func Gamertag(display, account string, attempt int) string {
	var b strings.Builder
	space := false
	for _, r := range display {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '-' || r == '.':
			space = true
		}
	}
	base := b.String()
	if base == "" || !(base[0] >= 'A' && base[0] <= 'Z' || base[0] >= 'a' && base[0] <= 'z') {
		base = "Player" + base
	}
	suffix := ""
	if attempt > 0 {
		h := sha256.Sum256([]byte(account + ":" + strconv.Itoa(attempt)))
		suffix = fmt.Sprintf("%d", (int(h[0])<<16|int(h[1])<<8|int(h[2]))%(9*pow10(min(attempt+1, 5)))+pow10(min(attempt+1, 5)))
	}
	if len(base)+len(suffix) > 15 {
		base = strings.TrimRight(base[:15-len(suffix)], " ")
	}
	return base + suffix
}

func pow10(n int) int {
	p := 1
	for ; n > 1; n-- {
		p *= 10
	}
	return p
}

// Service ensures and releases automatic identities.
type Service struct {
	Core  core.API
	Store *store.Store
}

// Ensure makes sure the account has an Xbox identity. It reports whether it
// created one. Inactive accounts are skipped. Safe to call concurrently and
// repeatedly.
func (s *Service) Ensure(ctx context.Context, account string) (bool, error) {
	defer projection.Lock()()
	if _, ok, err := s.Store.ActiveUserOf(ctx, account); err != nil || ok {
		return false, err // the display name is only the default for the first generation
	}
	acct, err := s.Core.GetAccount(ctx, account)
	if errors.Is(err, core.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if acct.Status != pb.AccountStatus_ACCOUNT_STATUS_ACTIVE {
		return false, nil
	}
	// A real (non-placeholder) active link without a users row is adopted as it
	// is: its xuid and public code are the identity (seed and legacy accounts).
	if l, err := s.Core.GetActiveLinkByAccount(ctx, account); err == nil {
		if !projection.Is(l.SubjectID) {
			if !xbaccountapi.ValidID(l.SubjectID) || !xbaccountapi.ValidGamertag(l.PublicCode) {
				return false, nil // not an identity we can describe: never invent one over it
			}
			err := s.Store.CommitAuto(ctx, store.User{XUID: l.SubjectID, CoreAccountID: account, Gamertag: l.PublicCode, LinkID: l.LinkID})
			return err == nil, err
		}
		if err := projection.Release(ctx, s.Core, account); err != nil {
			return false, err
		}
	} else if !errors.Is(err, core.ErrNotFound) {
		return false, err
	}
	for gen := 0; gen < maxGen; gen++ {
		xuid := XUID(account, gen)
		idem := "xbauto:" + xuid
		linkID, err := s.Core.ReserveLink(ctx, account, xuid, idem)
		if errors.Is(err, core.ErrConflict) || errors.Is(err, core.ErrPrecondition) {
			continue // subject taken or retired: next generation
		}
		if err != nil {
			return false, err
		}
		if err := s.Core.ActivateLink(ctx, linkID, idem+":activate"); errors.Is(err, core.ErrPrecondition) || errors.Is(err, core.ErrNotFound) {
			continue
		} else if err != nil {
			return false, err
		}
		for attempt := 0; attempt < 12; attempt++ {
			tag := Gamertag(acct.Name, account, attempt)
			if !xbaccountapi.ValidGamertag(tag) {
				continue
			}
			if _, err := s.Store.GetUserByGamertag(ctx, tag); err == nil {
				continue
			} else if !errors.Is(err, store.ErrNotFound) {
				return false, err
			}
			if err := s.Core.SetLinkPublicCode(ctx, linkID, tag); errors.Is(err, core.ErrConflict) {
				continue
			} else if err != nil {
				return false, err
			}
			err := s.Store.CommitAuto(ctx, store.User{XUID: xuid, CoreAccountID: account, Gamertag: tag, LinkID: linkID})
			if errors.Is(err, store.ErrConflict) {
				continue
			}
			return err == nil, err
		}
		return false, errors.New("autoid: no free gamertag")
	}
	return false, errors.New("autoid: no free xuid")
}

// Release retires the account's automatic identity before a real enrolment
// reserves its own link. Callers hold the projection gate. A no-op when the
// account has none.
func (s *Service) Release(ctx context.Context, account string) error {
	u, ok, err := s.Store.AutoIdentity(ctx, account)
	if err != nil || !ok {
		return err
	}
	if err := s.Core.UnlinkLink(ctx, u.LinkID, "xbauto:release:"+u.LinkID); err != nil && !errors.Is(err, core.ErrNotFound) && !errors.Is(err, core.ErrPrecondition) {
		return err
	}
	return s.Store.RetireAuto(ctx, account)
}

// Pass ensures every active core account once; counts only are logged.
func (s *Service) Pass(ctx context.Context) (created, failed int, err error) {
	after := ""
	for ctx.Err() == nil {
		ids, next, e := s.Core.ListAccounts(ctx, after, 200)
		if e != nil {
			return created, failed, e
		}
		for _, id := range ids {
			if ok, e := s.Ensure(ctx, id); e != nil {
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

// Run reconciles at start and then every interval.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	for ctx.Err() == nil {
		created, failed, err := s.Pass(ctx)
		if err != nil {
			log.Printf("xbox auto identities: core unavailable (created=%d failed=%d)", created, failed)
		} else if created > 0 || failed > 0 {
			log.Printf("xbox auto identities: created=%d failed=%d", created, failed)
		}
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}
