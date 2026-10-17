// SPDX-License-Identifier: AGPL-3.0-only

// Package social is xb-social's wire-independent domain layer for original
// Xbox users: the roster (friends, requests, blocks, invitations), friend
// operations, invitations and presence publishing, all backed by account core.
//
// Every method takes the viewer's XUID as bound by the gateway from the
// authenticated connection, never a value from the console's message. The
// viewer is re-resolved through xbaccountapi on each call, so a banned,
// unlinked or deleted user gets ErrDenied. Peers are named by XUID or gamertag
// and resolved the same way; a peer that cannot be admitted looks exactly like
// an unknown one.
//
// Projection rules (docs/xbox/native-service-architecture.md): a person
// appears only with an active "xbox" link and a published gamertag, carrying
// the link's real XUID. Accounts without one are never given a synthetic Xbox
// identity: they are omitted and counted in Roster.Omitted.
package social

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"sort"
	"sync"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-social/internal/core"
	"openpak/xb-live/services/xb-social/internal/friends"
)

var (
	// ErrDenied: the viewer is not admitted (banned, unlinked, deleted, unknown).
	ErrDenied = errors.New("social: viewer not admitted")
	// ErrUnavailable: a backend failed; never answered with partial data.
	ErrUnavailable = errors.New("social: backend unavailable")
	// ErrUnknownUser: the named person does not exist as an admitted Xbox user
	// (also what a person who blocked the viewer looks like).
	ErrUnknownUser = errors.New("social: unknown user")
	// ErrInvalid: the request is malformed or targets the viewer.
	ErrInvalid = errors.New("social: invalid request")
	// ErrNotPermitted: core policy refuses the operation.
	ErrNotPermitted = errors.New("social: not permitted")
	// ErrBlocked: the viewer has blocked that person; unblock first.
	ErrBlocked = errors.New("social: user is blocked")
	// ErrNoRequest: there is no such pending request.
	ErrNoRequest = errors.New("social: no such friend request")
	// ErrNotFriends: the two are not friends.
	ErrNotFriends = errors.New("social: not friends")
	// ErrNotReachable: the invitation target is not online in that Xbox title.
	ErrNotReachable = errors.New("social: target is not online in that title")
	// ErrNoInvite: no such invitation is waiting for the viewer.
	ErrNoInvite = errors.New("social: no such invitation")
	// ErrSuperseded: a newer connection of the same account owns presence.
	ErrSuperseded = errors.New("social: presence taken over by a newer connection")
)

// Person is a native Xbox identity.
type Person struct {
	XUID     string `json:"xuid"`
	Gamertag string `json:"gamertag"`
}

// Contact is a person with the time the relationship (or block) began.
type Contact struct {
	Person
	Since int64 `json:"since_unix,omitempty"`
}

// Invite is an invitation addressed to the viewer. Payload is the sender's
// opaque bytes (<= 4096), delivered untouched.
type Invite struct {
	ID      string `json:"id"`
	From    Person `json:"from"`
	TitleID string `json:"title_id"` // 8 lowercase hex digits
	Expires int64  `json:"expires_unix"`
	Payload []byte `json:"payload,omitempty"`
	nonce   string
	// fromAccount is the inviter's core account (never exposed).
	fromAccount string
}

// Omitted counts entries that exist in core but have no Xbox identity, so are
// not listed.
type Omitted struct {
	Friends, Incoming, Outgoing, Blocked, Invites int
}

// Roster is the native projection of everything social the viewer has.
type Roster struct {
	Friends  []friends.Friend `json:"friends"`
	Incoming []Contact        `json:"incoming"`
	Outgoing []Contact        `json:"outgoing"`
	Blocked  []Contact        `json:"blocked"`
	// Invites is the non-consuming inbox: pending invitations to the Xbox
	// namespace, without payload.
	Invites []Invite `json:"invites"`
	Omitted Omitted  `json:"omitted"`
	// BuddyVersion changes whenever the set of friends and requests (or a
	// gamertag in it) changes; BlockVersion likewise for blocks. 0 means empty.
	// Presence changes never move them.
	BuddyVersion uint32 `json:"buddy_version"`
	BlockVersion uint32 `json:"block_version"`
}

// BuddyCount is the number of friend-list entries (friends plus both request directions).
func (r *Roster) BuddyCount() int { return len(r.Friends) + len(r.Incoming) + len(r.Outgoing) }

type Service struct {
	Core     core.Backend
	Resolver xbaccountapi.Resolver
	// Presence, when set, lets invitations check the sender's own title.
	Presence *Presences
	// Hub, when set, hears about invitation answers.
	Hub *Hub
	// Concurrency bounds parallel link lookups (default 8).
	Concurrency int
	Now         func() time.Time

	polling sync.Map // account -> *sync.Mutex
	mu      sync.Mutex
	inbox   map[string]map[string]*inboxEntry // account -> invitation id
	answers map[string][]Answer               // inviter account -> answers not yet polled
}

type inboxEntry struct {
	inv   Invite
	acked bool
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) friendsSvc() *friends.Service {
	return &friends.Service{Core: s.Core, Resolver: s.Resolver, Concurrency: s.Concurrency}
}

// Actor admits the viewer and returns their core account. When gatewayAccount
// is non-empty it must agree with the resolver's answer.
func (s *Service) Actor(ctx context.Context, viewerXUID, gatewayAccount string) (string, error) {
	p, err := s.Resolver.ResolveUser(ctx, viewerXUID)
	switch {
	case err == nil:
	case errors.Is(err, xbaccountapi.ErrDenied), errors.Is(err, xbaccountapi.ErrNotFound), errors.Is(err, xbaccountapi.ErrInvalid):
		return "", ErrDenied
	default:
		log.Printf("social: resolve viewer: %v", err)
		return "", ErrUnavailable
	}
	if p.CoreAccountID == "" || p.Kind != xbaccountapi.KindUser || p.PrincipalID != viewerXUID || (gatewayAccount != "" && gatewayAccount != p.CoreAccountID) {
		return "", ErrDenied
	}
	return p.CoreAccountID, nil
}

// peer admits another Xbox user by XUID and returns their core account.
func (s *Service) peer(ctx context.Context, actor, xuid string) (string, error) {
	if !xbaccountapi.ValidID(xuid) {
		return "", ErrInvalid
	}
	p, err := s.Resolver.ResolveUser(ctx, xuid)
	switch {
	case err == nil:
	case errors.Is(err, xbaccountapi.ErrDenied), errors.Is(err, xbaccountapi.ErrNotFound), errors.Is(err, xbaccountapi.ErrInvalid):
		return "", ErrUnknownUser
	default:
		log.Printf("social: resolve peer: %v", err)
		return "", ErrUnavailable
	}
	if p.CoreAccountID == "" || p.PrincipalID != xuid {
		return "", ErrUnknownUser
	}
	if p.CoreAccountID == actor {
		return "", ErrInvalid
	}
	return p.CoreAccountID, nil
}

// PeerByGamertag resolves a typed gamertag to its XUID (the same admission
// rules as an XUID). Callers then use the XUID methods.
func (s *Service) PeerByGamertag(ctx context.Context, gamertag string) (string, error) {
	if !xbaccountapi.ValidGamertag(gamertag) {
		return "", ErrInvalid
	}
	p, err := s.Resolver.ResolveGamertag(ctx, gamertag)
	switch {
	case err == nil:
		return p.PrincipalID, nil
	case errors.Is(err, xbaccountapi.ErrDenied), errors.Is(err, xbaccountapi.ErrNotFound), errors.Is(err, xbaccountapi.ErrInvalid):
		return "", ErrUnknownUser
	}
	return "", ErrUnavailable
}

// people resolves accounts to Xbox identities concurrently. Accounts without a
// usable identity are absent from the result; any backend failure fails all.
func (s *Service) people(ctx context.Context, ids []string) (map[string]Person, error) {
	out := make(map[string]Person, len(ids))
	var mu sync.Mutex
	var failed int
	n := s.Concurrency
	if n <= 0 {
		n = 8
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			l, err := s.Core.ActiveLink(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				if xbaccountapi.ValidID(l.SubjectID) && l.PublicCode != "" {
					out[id] = Person{l.SubjectID, l.PublicCode}
				}
			case errors.Is(err, core.ErrNotFound):
			default:
				failed++
				log.Printf("roster: link lookup failed (skipped): %v", err)
			}
		}()
	}
	wg.Wait()
	if failed > 0 && failed == len(ids) {
		return nil, fmt.Errorf("%w: every identity lookup failed (%d)", ErrUnavailable, failed)
	}
	return out, nil
}

func contacts(fs []core.Friend, ppl map[string]Person, self string) (out []Contact, omitted int) {
	out = []Contact{}
	seen := map[string]bool{}
	for _, f := range fs {
		p, ok := ppl[f.AccountID]
		if !ok || f.AccountID == self || seen[p.XUID] {
			omitted++
			continue
		}
		seen[p.XUID] = true
		out = append(out, Contact{p, f.Since})
	}
	return out, omitted
}

// Roster builds the viewer's projection. Any backend failure is ErrUnavailable.
func (s *Service) Roster(ctx context.Context, viewerXUID, gatewayAccount string) (*Roster, error) {
	account, err := s.Actor(ctx, viewerXUID, gatewayAccount)
	if err != nil {
		return nil, err
	}
	return s.RosterOf(ctx, account)
}

// RosterOf is Roster for an already admitted account.
func (s *Service) RosterOf(ctx context.Context, account string) (*Roster, error) {
	fl, err := s.friendsSvc().FriendsOf(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("%w: friends: %v", ErrUnavailable, err)
	}
	in, err1 := s.Core.ListIncoming(ctx, account)
	out, err2 := s.Core.ListOutgoing(ctx, account)
	bl, err3 := s.Core.ListBlocks(ctx, account)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// The invitation inbox is not part of the friend list: if core cannot
	// list it (or does not offer the call) the roster is still valid without it.
	inv, err4 := s.Core.ListInvitations(ctx, account, 100)
	if err4 != nil {
		log.Printf("roster: invitation inbox unavailable (omitted): %v", err4)
		inv = nil
	}
	var ids []string
	for _, f := range in {
		ids = append(ids, f.AccountID)
	}
	for _, f := range out {
		ids = append(ids, f.AccountID)
	}
	for _, b := range bl {
		ids = append(ids, b.AccountID)
	}
	for _, i := range inv {
		if i.Namespace == core.Namespace {
			ids = append(ids, i.From)
		}
	}
	ppl, err := s.people(ctx, dedupe(ids))
	if err != nil {
		return nil, err
	}
	r := &Roster{Friends: fl.Friends, Omitted: Omitted{Friends: fl.Omitted}}
	r.Incoming, r.Omitted.Incoming = contacts(in, ppl, account)
	r.Outgoing, r.Omitted.Outgoing = contacts(out, ppl, account)
	r.Blocked = []Contact{}
	for _, b := range bl {
		p, ok := ppl[b.AccountID]
		if !ok || b.AccountID == account {
			r.Omitted.Blocked++
			continue
		}
		r.Blocked = append(r.Blocked, Contact{p, b.At})
	}
	r.Invites = []Invite{}
	for _, i := range inv {
		if i.Namespace != core.Namespace {
			continue
		}
		p, ok := ppl[i.From]
		if !ok {
			r.Omitted.Invites++
			continue
		}
		r.Invites = append(r.Invites, Invite{ID: i.ID, From: p, TitleID: i.TitleID, Expires: i.Expires})
	}
	var buddy, block []string
	for _, f := range r.Friends {
		buddy = append(buddy, "f"+f.XUID+f.Gamertag)
	}
	for _, c := range r.Incoming {
		buddy = append(buddy, "i"+c.XUID+c.Gamertag)
	}
	for _, c := range r.Outgoing {
		buddy = append(buddy, "o"+c.XUID+c.Gamertag)
	}
	for _, c := range r.Blocked {
		block = append(block, "b"+c.XUID+c.Gamertag)
	}
	r.BuddyVersion, r.BlockVersion = version(buddy), version(block)
	return r, nil
}

// Filter drops the parts of the roster the flags leave out and recomputes the
// versions, for isolating which kind of entry a console rejects.
func (r *Roster) Filter(keepFriends, requests, blocks bool) {
	if !keepFriends {
		r.Friends = []friends.Friend{}
	}
	if !requests {
		r.Incoming, r.Outgoing = []Contact{}, []Contact{}
	}
	if !blocks {
		r.Blocked = []Contact{}
	}
	var buddy, block []string
	for _, f := range r.Friends {
		buddy = append(buddy, "f"+f.XUID+f.Gamertag)
	}
	for _, c := range r.Incoming {
		buddy = append(buddy, "i"+c.XUID+c.Gamertag)
	}
	for _, c := range r.Outgoing {
		buddy = append(buddy, "o"+c.XUID+c.Gamertag)
	}
	for _, c := range r.Blocked {
		block = append(block, "b"+c.XUID+c.Gamertag)
	}
	r.BuddyVersion, r.BlockVersion = version(buddy), version(block)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// version is an order-independent 32-bit digest of a membership set; 0 only
// for the empty set.
func version(parts []string) uint32 {
	if len(parts) == 0 {
		return 0
	}
	sort.Strings(parts)
	h := fnv.New32a()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	switch v := h.Sum32(); v {
	case 0:
		return 1
	case 0xfffffffd, 0xfffffffe, 0xffffffff:
		// 0xffffffff is the console's own "force a resend" stamp, and it rejects
		// a list whose version is -1 or -2 (validation in the AliveReply parser).
		return 0xfffffffc
	default:
		return v
	}
}
