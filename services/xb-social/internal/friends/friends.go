// SPDX-License-Identifier: AGPL-3.0-only

// Package friends projects the core friend graph and live presence into the
// native Xbox view. Only real data is returned: a friend appears only when
// they hold an active "xbox" link with a published gamertag, carrying their
// real XUID. Friends without a native identity are omitted and counted, never
// replaced by a synthetic XUID or a gamertag derived from a display name.
//
// The viewer is identified by XUID and resolved through xbaccountapi so a
// banned, unlinked or deleted viewer gets nothing. The caller (xb-gateway)
// binds the viewer from its authenticated connection; it is never client input.
package friends

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-social/internal/core"
)

var (
	ErrDenied      = errors.New("friends: viewer not admitted")
	ErrUnavailable = errors.New("friends: backend unavailable")
)

type State string

const (
	Online  State = "online"
	Offline State = "offline"
)

// Presence is the native projection. TitleID is set only when the live
// session belongs to the Xbox namespace (titles of other platforms have no
// Xbox title identity); such a friend is Online with no title.
type Presence struct {
	State     State  `json:"state"`
	TitleID   string `json:"title_id,omitempty"`
	SinceUnix int64  `json:"since_unix,omitempty"`
}

type Friend struct {
	XUID         string   `json:"xuid"`
	Gamertag     string   `json:"gamertag"`
	FriendsSince int64    `json:"friends_since_unix,omitempty"`
	LastSeen     int64    `json:"last_seen_unix,omitempty"`
	Presence     Presence `json:"presence"`
}

// List is the viewer's native friend list. Omitted counts accepted friends
// that have no usable native identity (not an error, and not listed).
type List struct {
	Friends []Friend `json:"friends"`
	Omitted int      `json:"omitted"`
}

type Service struct {
	Core     core.API
	Resolver xbaccountapi.Resolver
	// Concurrency bounds parallel link lookups (default 8).
	Concurrency int
}

func (s *Service) viewer(ctx context.Context, xuid string) (string, error) {
	p, err := s.Resolver.ResolveUser(ctx, xuid)
	switch {
	case err == nil:
		return p.CoreAccountID, nil
	case errors.Is(err, xbaccountapi.ErrDenied), errors.Is(err, xbaccountapi.ErrNotFound), errors.Is(err, xbaccountapi.ErrInvalid):
		return "", ErrDenied
	default:
		return "", ErrUnavailable
	}
}

// Friends returns the viewer's accepted friends with presence.
func (s *Service) Friends(ctx context.Context, viewerXUID string) (List, error) {
	account, err := s.viewer(ctx, viewerXUID)
	if err != nil {
		return List{}, err
	}
	return s.FriendsOf(ctx, account)
}

// FriendsOf is Friends for a core account the caller has already admitted.
func (s *Service) FriendsOf(ctx context.Context, account string) (List, error) {
	raw, err := s.Core.ListFriends(ctx, account)
	if err != nil {
		return List{}, fmt.Errorf("%w: ListFriends: %v", ErrUnavailable, err)
	}
	type slot struct {
		link core.Link
		ok   bool
	}
	slots := make([]slot, len(raw))
	errs := make([]error, len(raw))
	n := s.Concurrency
	if n <= 0 {
		n = 8
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, f := range raw {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			l, err := s.Core.ActiveLink(ctx, f.AccountID)
			switch {
			case err == nil:
				slots[i] = slot{l, true}
			case errors.Is(err, core.ErrNotFound):
			default:
				errs[i] = err
				log.Printf("friends: link lookup failed for a friend (skipped): %v", err)
			}
		}()
	}
	wg.Wait()
	// One friend whose link cannot be read is omitted and counted; only a
	// wholesale failure (every lookup failed) is an outage, never a half list.
	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
		}
	}
	if failed > 0 && failed == len(raw) {
		return List{}, fmt.Errorf("%w: every friend link lookup failed (%d): %v", ErrUnavailable, failed, errors.Join(errs...))
	}

	out := List{Friends: []Friend{}}
	var ids []string
	var linked []int
	seen := map[string]bool{}
	for i, f := range raw {
		l := slots[i].link
		if !slots[i].ok || !xbaccountapi.ValidID(l.SubjectID) || l.PublicCode == "" || seen[l.SubjectID] || f.AccountID == account {
			out.Omitted++
			continue
		}
		seen[l.SubjectID] = true
		out.Friends = append(out.Friends, Friend{XUID: l.SubjectID, Gamertag: l.PublicCode, FriendsSince: f.Since, LastSeen: f.LastSeen, Presence: Presence{State: Offline}})
		ids = append(ids, f.AccountID)
		linked = append(linked, i)
	}
	if len(ids) == 0 {
		return out, nil
	}

	// Presence only for friends the viewer may discover (blocks are enforced by core).
	visible := make([]string, 0, len(ids))
	visibleAt := map[string]int{}
	for j, id := range ids {
		ok, err := s.Core.CanDiscover(ctx, account, id)
		if err != nil {
			log.Printf("friends: CanDiscover failed (shown offline): %v", err)
			continue
		}
		if ok {
			visible = append(visible, id)
			visibleAt[id] = j
		}
	}
	if len(visible) == 0 {
		return out, nil
	}
	pres, err := s.Core.GetPresence(ctx, visible)
	if err != nil {
		log.Printf("friends: GetPresence failed (all shown offline): %v", err)
		return out, nil // the list itself is real; presence is a best-effort overlay
	}
	for _, p := range pres {
		j, ok := visibleAt[p.AccountID]
		if !ok {
			continue // core answered for someone we did not ask about
		}
		cur := &out.Friends[j].Presence
		if p.Namespace == core.Namespace {
			*cur = Presence{State: Online, TitleID: p.TitleID, SinceUnix: p.SinceUnix}
		} else if cur.State == Offline {
			*cur = Presence{State: Online, SinceUnix: p.SinceUnix}
		}
	}
	return out, nil
}

// Presence returns the entries of the viewer's friend list for the requested
// XUIDs. XUIDs that are not the viewer's friends are silently absent: this is
// not a lookup service for arbitrary users.
func (s *Service) Presence(ctx context.Context, viewerXUID string, xuids []string) ([]Friend, error) {
	list, err := s.Friends(ctx, viewerXUID)
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(xuids))
	for _, x := range xuids {
		want[x] = true
	}
	var out []Friend
	for _, f := range list.Friends {
		if want[f.XUID] {
			out = append(out, f)
		}
	}
	return out, nil
}
