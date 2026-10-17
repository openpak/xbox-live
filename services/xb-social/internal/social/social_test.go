// SPDX-License-Identifier: AGPL-3.0-only

package social

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-social/internal/core"
	"openpak/xb-live/services/xb-social/internal/coretest"
)

const (
	xA = "0009000000000001"
	xB = "0009000000000002"
	xC = "0009000000000003"
	xD = "0009000000000004"
)

// resolver is a stand-in for xb-account: admission follows the fake core, so a
// ban or unlink takes effect on the next call, as the real resolver does.
type resolver struct {
	c    *coretest.Core
	mu   sync.Mutex
	fail error
}

func (r *resolver) ResolveUser(ctx context.Context, xuid string) (xbaccountapi.Principal, error) {
	if r.fail != nil {
		return xbaccountapi.Principal{}, r.fail
	}
	for _, a := range []string{"alice", "bob", "carol", "dave"} {
		l, ok := r.c.LinkOf(a)
		if ok && l.Subject == xuid {
			if r.c.Banned(a) {
				return xbaccountapi.Principal{}, &xbaccountapi.DeniedError{Principal: xbaccountapi.Principal{Kind: xbaccountapi.KindUser, Status: xbaccountapi.StatusBanned}}
			}
			return xbaccountapi.Principal{Kind: xbaccountapi.KindUser, PrincipalID: xuid, CoreAccountID: a, Status: xbaccountapi.StatusActive, Gamertag: l.Code}, nil
		}
	}
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}
func (r *resolver) ResolveDevice(context.Context, string) (xbaccountapi.Principal, error) {
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}
func (r *resolver) ResolveGamertag(ctx context.Context, tag string) (xbaccountapi.Principal, error) {
	for _, a := range []string{"alice", "bob", "carol", "dave"} {
		if l, ok := r.c.LinkOf(a); ok && l.Code == tag {
			return r.ResolveUser(ctx, l.Subject)
		}
	}
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}

type env struct {
	t *testing.T
	c *coretest.Core
	s *Service
	p *Presences
}

func newEnv(t *testing.T) *env {
	c := coretest.New()
	for _, n := range []string{"alice", "bob", "carol", "dave"} {
		c.AddAccount(n, n)
	}
	c.LinkXbox("alice", xA, "Alice")
	c.LinkXbox("bob", xB, "Bob")
	c.LinkXbox("carol", xC, "Carol")
	// dave only has a Switch link: no Xbox identity.
	c.AddLink("dave", "switch", "sw-1", "SW-1")
	p := &Presences{Core: c, Now: c.Now}
	s := &Service{Core: c, Resolver: &resolver{c: c}, Presence: p, Now: c.Now}
	return &env{t, c, s, p}
}

// step advances the clock the way production does, with the keepalive running every 10 s.
func (e *env) step(d time.Duration) {
	for ; d > 0; d -= 10 * time.Second {
		e.c.Advance(min(d, 10*time.Second))
		e.p.Tick(context.Background())
	}
}

func (e *env) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) befriend(a, b, ax, bx string) {
	e.t.Helper()
	ctx := context.Background()
	if _, err := e.s.SendFriendRequest(ctx, ax, "", bx); err != nil {
		e.t.Fatal(err)
	}
	e.must(e.s.AcceptFriendRequest(ctx, bx, "", ax))
}

func TestRosterProjection(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.befriend("alice", "bob", xA, xB)
	// dave (no Xbox link) is a core friend of alice: counted, never listed.
	e.must(e.c.RequestFriend(ctx, "dave", "alice", ""))
	e.must(e.c.AcceptFriend(ctx, "alice", "dave", ""))
	// carol asked alice; alice asked nobody; alice blocked nobody yet.
	if _, err := e.s.SendFriendRequest(ctx, xC, "", xA); err != nil {
		t.Fatal(err)
	}
	r, err := e.s.Roster(ctx, xA, "")
	e.must(err)
	if len(r.Friends) != 1 || r.Friends[0].XUID != xB || r.Friends[0].Gamertag != "Bob" || r.Omitted.Friends != 1 {
		t.Fatalf("friends %+v omitted %+v", r.Friends, r.Omitted)
	}
	if len(r.Incoming) != 1 || r.Incoming[0].XUID != xC || len(r.Outgoing) != 0 || len(r.Blocked) != 0 {
		t.Fatalf("requests %+v %+v", r.Incoming, r.Outgoing)
	}
	if r.BuddyVersion == 0 || r.BlockVersion != 0 || r.BuddyCount() != 2 {
		t.Fatalf("versions %d %d count %d", r.BuddyVersion, r.BlockVersion, r.BuddyCount())
	}
	v1 := r.BuddyVersion
	// Presence changes leave the list version alone.
	e.must(e.p.Publish(ctx, "bob", xB, TitleKey(0x4d530004), 1, 0))
	r, _ = e.s.Roster(ctx, xA, "")
	if r.BuddyVersion != v1 || r.Friends[0].Presence.State != "online" || r.Friends[0].Presence.TitleID != "4d530004" {
		t.Fatalf("presence %+v version %d", r.Friends[0].Presence, r.BuddyVersion)
	}
	// Accepting changes it.
	e.must(e.s.AcceptFriendRequest(ctx, xA, "", xC))
	r, _ = e.s.Roster(ctx, xA, "")
	if r.BuddyVersion == v1 || len(r.Friends) != 2 {
		t.Fatalf("version did not move: %d", r.BuddyVersion)
	}
	// A blocked friend appears offline and the block list reflects it.
	e.must(e.s.Block(ctx, xA, "", xB))
	r, _ = e.s.Roster(ctx, xA, "")
	if len(r.Blocked) != 1 || r.Blocked[0].XUID != xB || r.BlockVersion == 0 {
		t.Fatalf("blocks %+v", r.Blocked)
	}
	for _, f := range r.Friends {
		if f.XUID == xB {
			t.Fatalf("blocked user is still a friend: %+v", f)
		}
	}
}

func TestRosterFailsWholeOnBackendError(t *testing.T) {
	for _, op := range []string{"ListFriends", "ListIncoming", "ListOutgoing", "ListBlocks", "ActiveLink"} {
		e := newEnv(t)
		e.befriend("alice", "bob", xA, xB)
		e.c.Fail = func(o string) error {
			if o == op {
				return core.ErrUnavailable
			}
			return nil
		}
		if _, err := e.s.Roster(context.Background(), xA, ""); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v", op, err)
		}
	}
}

func TestViewerMustBeAdmitted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.s.Roster(ctx, xD, ""); !errors.Is(err, ErrDenied) { // no xbox link
		t.Errorf("unlinked: %v", err)
	}
	if _, err := e.s.Roster(ctx, xA, "bob"); !errors.Is(err, ErrDenied) { // gateway account disagrees
		t.Errorf("mismatch: %v", err)
	}
	e.c.Ban("alice")
	if _, err := e.s.Roster(ctx, xA, ""); !errors.Is(err, ErrDenied) {
		t.Errorf("banned: %v", err)
	}
	e.s.Resolver.(*resolver).fail = xbaccountapi.ErrUnavailable
	if _, err := e.s.Roster(ctx, xB, ""); !errors.Is(err, ErrUnavailable) {
		t.Errorf("resolver down: %v", err)
	}
}

func TestFriendRequestFlows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	send := func(from, to string) (Outcome, error) { return e.s.SendFriendRequest(ctx, from, "", to) }
	if o, err := send(xA, xB); o != Requested || err != nil {
		t.Fatal(o, err)
	}
	if o, err := send(xA, xB); o != Requested || err != nil { // idempotent
		t.Fatal(o, err)
	}
	if _, err := send(xA, xA); !errors.Is(err, ErrInvalid) {
		t.Errorf("self: %v", err)
	}
	if _, err := send(xA, xD); !errors.Is(err, ErrUnknownUser) { // no xbox identity: not fabricated
		t.Errorf("non-xbox target: %v", err)
	}
	if _, err := send(xA, "0009000000000099"); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("unknown target: %v", err)
	}
	// Crossed request: bob asks alice back, becoming friends.
	if o, err := send(xB, xA); o != Accepted || err != nil {
		t.Fatal(o, err)
	}
	if o, _ := send(xA, xB); o != AlreadyFriends {
		t.Errorf("again: %v", o)
	}
	// Decline must never unfriend; remove only works on friends.
	if err := e.s.DeclineFriendRequest(ctx, xA, "", xB); !errors.Is(err, ErrNoRequest) {
		t.Errorf("decline a friend: %v", err)
	}
	if err := e.s.RemoveFriend(ctx, xA, "", xC); !errors.Is(err, ErrNotFriends) {
		t.Errorf("remove stranger: %v", err)
	}
	e.must(e.s.RemoveFriend(ctx, xA, "", xB))
	// carol asks, alice declines; carol asks again and cancels.
	send(xC, xA)
	e.must(e.s.DeclineFriendRequest(ctx, xA, "", xC))
	if r, _ := e.s.Roster(ctx, xA, ""); len(r.Incoming)+len(r.Friends) != 0 {
		t.Errorf("not declined: %+v", r)
	}
	send(xC, xA)
	e.must(e.s.CancelFriendRequest(ctx, xC, "", xA))
	if err := e.s.AcceptFriendRequest(ctx, xA, "", xC); !errors.Is(err, ErrNoRequest) {
		t.Errorf("accept after cancel: %v", err)
	}
	// Lookup by gamertag.
	if x, err := e.s.PeerByGamertag(ctx, "Carol"); err != nil || x != xC {
		t.Errorf("gamertag %q %v", x, err)
	}
}

func TestBlockSemantics(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.befriend("alice", "bob", xA, xB)
	e.must(e.p.Publish(ctx, "bob", xB, TitleKey(0x41430001), 1, 0))
	e.must(e.s.Block(ctx, xA, "", xB))
	// The block removed the friendship in both directions.
	if r, _ := e.s.Roster(ctx, xB, ""); len(r.Friends) != 0 {
		t.Errorf("bob still sees alice: %+v", r.Friends)
	}
	// Alice cannot re-request while blocking; bob cannot tell he is blocked.
	if _, err := e.s.SendFriendRequest(ctx, xA, "", xB); !errors.Is(err, ErrBlocked) {
		t.Errorf("blocker request: %v", err)
	}
	if _, err := e.s.SendFriendRequest(ctx, xB, "", xA); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("blocked request: %v", err)
	}
	e.must(e.s.Unblock(ctx, xA, "", xB))
	if r, _ := e.s.Roster(ctx, xA, ""); len(r.Blocked) != 0 || len(r.Friends) != 0 {
		t.Errorf("unblock restored too much: %+v", r)
	}
	// Block recorded even if the follow-up removal fails.
	e.c.Fail = func(op string) error {
		if op == "RemoveFriend" {
			return core.ErrUnavailable
		}
		return nil
	}
	if err := e.s.Block(ctx, xA, "", xC); !errors.Is(err, ErrUnavailable) {
		t.Errorf("block removal failure: %v", err)
	}
	e.c.Fail = nil
	if r, _ := e.s.Roster(ctx, xA, ""); len(r.Blocked) != 1 {
		t.Errorf("block lost: %+v", r.Blocked)
	}
}

func TestPresenceSemantics(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	t1, t2 := TitleKey(0x4d530004), TitleKey(0x41430001)
	e.must(e.p.Publish(ctx, "alice", xA, t1, 1, 0))
	if got := e.c.Sessions("alice"); len(got) != 1 || got[0] != "xbox/"+t1 {
		t.Fatalf("sessions %v", got)
	}
	// Same title: renewal, no new registration (it would orphan invitations).
	regs := count(e.c.Calls, "RegisterSession")
	e.must(e.p.Publish(ctx, "alice", xA, t1, 1, 0))
	if count(e.c.Calls, "RegisterSession") != regs {
		t.Error("re-registered for the same title")
	}
	// Title change: new session, old one gone.
	e.must(e.p.Publish(ctx, "alice", xA, t2, 1, 0))
	if got := e.c.Sessions("alice"); len(got) != 1 || got[0] != "xbox/"+t2 {
		t.Fatalf("after title change %v", got)
	}
	// Dashboard (title 0) is online with no title.
	e.must(e.p.Publish(ctx, "alice", xA, TitleKey(0), 1, 0))
	if got := e.c.Sessions("alice"); len(got) != 1 || got[0] != "xbox/" {
		t.Fatalf("dashboard %v", got)
	}
	// An older connection generation cannot take presence back.
	e.must(e.p.Publish(ctx, "alice", xA, t1, 5, 0))
	if err := e.p.Publish(ctx, "alice", xA, t2, 4, 0); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("old generation: %v", err)
	}
	// ...and its disconnect leaves the newer session alone.
	e.must(e.p.Disconnect(ctx, "alice", 4))
	if got := e.c.Sessions("alice"); len(got) != 1 || got[0] != "xbox/"+t1 {
		t.Fatalf("stale disconnect %v", got)
	}
	e.must(e.p.Disconnect(ctx, "alice", 5))
	if got := e.c.Sessions("alice"); len(got) != 0 {
		t.Fatalf("after disconnect %v", got)
	}
	// Banned account: core refuses the session, nothing is published.
	e.c.Ban("bob")
	if err := e.p.Publish(ctx, "bob", xB, t1, 1, 0); err == nil || len(e.c.Sessions("bob")) != 0 {
		t.Fatalf("banned publish: %v", err)
	}
	// Core down: honest error, nothing recorded.
	e.c.Fail = func(string) error { return core.ErrUnavailable }
	if err := e.p.Publish(ctx, "carol", xC, t1, 1, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("core down: %v", err)
	}
	e.c.Fail = nil
	if _, ok := e.p.Current("carol"); ok {
		t.Error("carol online after failed publish")
	}
}

func count(calls []string, op string) (n int) {
	for _, c := range calls {
		if c == op {
			n++
		}
	}
	return n
}

func TestPresenceKeepaliveAndExpiry(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.must(e.p.Publish(ctx, "alice", xA, TitleKey(0x4d530004), 1, 100*time.Second))
	// Core's lease is 30 s; Tick every 10 s keeps it alive inside the deadline.
	for range 9 {
		e.c.Advance(10 * time.Second)
		e.p.Tick(ctx)
		if len(e.c.Sessions("alice")) != 1 {
			t.Fatalf("lost at %v", e.c.Now())
		}
	}
	// Past the deadline (100 s) the next Tick expires it and stops renewing.
	e.c.Advance(15 * time.Second)
	e.p.Tick(ctx)
	if len(e.c.Sessions("alice")) != 0 {
		t.Fatal("still online after deadline")
	}
	if _, ok := e.p.Current("alice"); ok {
		t.Fatal("tracker kept it")
	}
	// Without Tick (xb-social died) the core lease lapses by itself.
	e.must(e.p.Publish(ctx, "bob", xB, "", 1, time.Hour))
	e.c.Advance(31 * time.Second)
	if len(e.c.Sessions("bob")) != 0 {
		t.Fatal("core lease did not lapse")
	}
	// A lease lost mid-way is registered again by Tick.
	e.must(e.p.Publish(ctx, "carol", xC, "", 1, time.Hour))
	e.c.Advance(31 * time.Second)
	e.p.Tick(ctx)
	if len(e.c.Sessions("carol")) != 1 {
		t.Fatal("not re-registered")
	}
}

func TestInviteFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	title := uint32(0x4d530004)
	e.befriend("alice", "bob", xA, xB)
	send := func(payload string) error {
		return e.s.SendInvite(ctx, xA, "", xB, title, []byte(payload), 0)
	}
	if err := send("room"); !errors.Is(err, ErrNotReachable) { // alice not in the title yet
		t.Fatalf("sender offline: %v", err)
	}
	e.must(e.p.Publish(ctx, "alice", xA, TitleKey(title), 1, 0))
	if err := send("room"); !errors.Is(err, ErrNotReachable) { // bob offline
		t.Fatalf("target offline: %v", err)
	}
	// Bob online on another platform with the same title number: not a target.
	e.c.AddForeignSession("bob", "switch", TitleKey(title))
	e.c.Advance(time.Second)
	if err := send("room"); !errors.Is(err, ErrNotReachable) {
		t.Fatalf("foreign session: %v", err)
	}
	e.c.Advance(time.Second) // the Xbox session is the newest: it is what core resolves
	e.must(e.p.Publish(ctx, "bob", xB, TitleKey(title), 1, 0))
	if err := e.s.SendInvite(ctx, xA, "", xB, title, nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty payload: %v", err)
	}
	if err := e.s.SendInvite(ctx, xA, "", xC, title, []byte("x"), 0); !errors.Is(err, ErrNotPermitted) { // not friends
		t.Fatalf("stranger: %v", err)
	}
	e.must(send("room-1"))

	// Roster shows it without consuming it.
	r, _ := e.s.Roster(ctx, xB, "")
	if len(r.Invites) != 1 || r.Invites[0].From.XUID != xA || r.Invites[0].TitleID != TitleKey(title) {
		t.Fatalf("inbox %+v", r.Invites)
	}
	// A failed delivery acknowledges nothing: core redelivers after its window.
	if _, err := e.s.PollInvites(ctx, xB, "", func([]Invite) error { return errors.New("wire down") }); err == nil {
		t.Fatal("deliver error swallowed")
	}
	e.step(61 * time.Second)
	var got []Invite
	n, err := e.s.PollInvites(ctx, xB, "", func(in []Invite) error { got = append(got, in...); return nil })
	if err != nil || n != 1 || len(got) != 1 || string(got[0].Payload) != "room-1" || got[0].From.Gamertag != "Alice" {
		t.Fatalf("poll %d %v %+v", n, err, got)
	}
	// Idempotent: polling again delivers nothing new.
	e.step(61 * time.Second)
	n, err = e.s.PollInvites(ctx, xB, "", func(in []Invite) error { t.Fatalf("redelivered %+v", in); return nil })
	if err != nil || n != 0 {
		t.Fatalf("second poll %d %v", n, err)
	}
	in, err := e.s.AcceptInvite(ctx, xB, "", got[0].ID)
	if err != nil || in.From.XUID != xA {
		t.Fatalf("accept %+v %v", in, err)
	}
	if _, err := e.s.AcceptInvite(ctx, xB, "", "nope"); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("accept unknown: %v", err)
	}
	// Someone else's inbox is not readable.
	if _, err := e.s.AcceptInvite(ctx, xA, "", got[0].ID); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("accept by other: %v", err)
	}
}

func TestInviteAckFailureIsRetriedNotRedelivered(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	title := uint32(0x4d530004)
	e.befriend("alice", "bob", xA, xB)
	e.must(e.p.Publish(ctx, "alice", xA, TitleKey(title), 1, 0))
	e.must(e.p.Publish(ctx, "bob", xB, TitleKey(title), 1, 0))
	e.must(e.s.SendInvite(ctx, xA, "", xB, title, []byte("p"), 0))
	e.c.Fail = func(op string) error {
		if op == "AckInvitations" {
			return core.ErrUnavailable
		}
		return nil
	}
	delivered := 0
	deliver := func(in []Invite) error { delivered += len(in); return nil }
	if _, err := e.s.PollInvites(ctx, xB, "", deliver); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ack failure: %v", err)
	}
	e.c.Fail = nil
	e.step(61 * time.Second)
	if _, err := e.s.PollInvites(ctx, xB, "", deliver); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Fatalf("delivered %d times", delivered)
	}
	e.step(61 * time.Second)
	e.s.PollInvites(ctx, xB, "", deliver)
	if delivered != 1 {
		t.Fatalf("delivered %d times after ack", delivered)
	}
}

func TestInviteDecline(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	title := uint32(0x4d530004)
	e.befriend("alice", "bob", xA, xB)
	e.must(e.p.Publish(ctx, "alice", xA, TitleKey(title), 1, 0))
	e.must(e.p.Publish(ctx, "bob", xB, TitleKey(title), 1, 0))
	e.must(e.s.SendInvite(ctx, xA, "", xB, title, []byte("p"), 0))
	r, _ := e.s.Roster(ctx, xB, "")
	e.must(e.s.DeclineInvite(ctx, xB, "", r.Invites[0].ID))
	if r, _ := e.s.Roster(ctx, xB, ""); len(r.Invites) != 0 {
		t.Fatalf("still waiting: %+v", r.Invites)
	}
	if err := e.s.DeclineInvite(ctx, xB, "", r.Invites[0].ID); !errors.Is(err, ErrNoInvite) {
		t.Fatalf("decline twice: %v", err)
	}
}

func TestPollerCursorDedupeAndRevocation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cur := FileCursor{Path: t.TempDir() + "/cursor"}
	hub := &Hub{}
	bobSub := hub.Subscribe("bob")
	aliceSub := hub.Subscribe("alice")
	p := &Poller{Core: e.c, Cursor: cur, Hub: hub, Presence: e.p}
	// First start begins at the head: earlier history is not replayed.
	e.c.Emit("account_banned", "carol", "", "")
	if n, err := p.Step(ctx); err != nil || n != 0 {
		t.Fatalf("first step %d %v", n, err)
	}
	if v, _ := cur.Load(); v != 1 {
		t.Fatalf("cursor %d", v)
	}
	e.must(e.p.Publish(ctx, "alice", xA, "", 1, time.Hour))
	e.befriend("alice", "bob", xA, xB) // friend_requested(bob), friend_accepted(alice)
	e.c.Unlink("alice", "switch")      // someone else's unlink: ignored
	if len(e.c.Sessions("alice")) != 1 {
		t.Fatal("setup")
	}
	n, err := p.Step(ctx)
	e.must(err)
	if n != 3 {
		t.Fatalf("handled %d", n)
	}
	if got := (<-bobSub.C).Kind; got != NoticeFriendRequested {
		t.Errorf("bob got %v", got)
	}
	if got := (<-aliceSub.C).Kind; got != NoticeFriendAccepted {
		t.Errorf("alice got %v", got)
	}
	if len(e.c.Sessions("alice")) != 1 {
		t.Fatal("switch unlink ended Xbox presence")
	}
	// Xbox unlink ends presence and notifies; replay of the same page is a no-op.
	e.c.Unlink("alice", "xbox")
	if _, err := p.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.c.Sessions("alice")) != 0 {
		t.Fatal("presence survived unlink")
	}
	if got := (<-aliceSub.C).Kind; got != NoticeRevoked {
		t.Errorf("alice got %v", got)
	}
	// A restart resumes from the file and handles nothing twice.
	p2 := &Poller{Core: e.c, Cursor: cur, Hub: hub, Presence: e.p}
	if n, err := p2.Step(ctx); err != nil || n != 0 {
		t.Fatalf("after restart %d %v", n, err)
	}
	// Cursor rewound (lost save): the per-process dedupe stops double effects.
	cur.Save(1)
	if n, _ := p.Step(ctx); n != 0 {
		t.Fatalf("redelivered %d", n)
	}
}

func TestPollerRetriesFailedEffect(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cur := &MemCursor{}
	cur.Save(0)
	hub := &Hub{}
	p := &Poller{Core: e.c, Cursor: cur, Hub: hub, Presence: e.p}
	e.must(e.p.Publish(ctx, "bob", xB, "", 1, time.Hour))
	e.c.Ban("bob")
	e.c.Fail = func(op string) error {
		if op == "ExpireSession" {
			return core.ErrUnavailable
		}
		return nil
	}
	if _, err := p.Step(ctx); err == nil {
		t.Fatal("failure swallowed")
	}
	if v, _ := cur.Load(); v != 0 {
		t.Fatalf("cursor advanced past an unapplied event: %d", v)
	}
	e.c.Fail = nil
	if n, err := p.Step(ctx); err != nil || n != 1 {
		t.Fatalf("retry %d %v", n, err)
	}
	if _, ok := e.p.Current("bob"); ok {
		t.Fatal("still tracked")
	}
}

func TestHubDropsOldestWhenSlow(t *testing.T) {
	h := &Hub{}
	s := h.Subscribe("a")
	for range 40 {
		h.Publish(Notice{Kind: NoticePresence, Account: "a"})
	}
	if len(s.C) != 16 || !s.Lost() || s.Lost() {
		t.Fatalf("len %d", len(s.C))
	}
	s.Close()
	h.Publish(Notice{Account: "a"}) // no subscribers: no panic
}

func TestPushSourceTargetsOnlyOnlineXboxUsers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	hub := &Hub{}
	var got []Push
	PushSource(hub, e.p, func(p Push) { got = append(got, p) })
	e.must(e.p.Publish(ctx, "bob", xB, "", 1, 0))
	hub.Publish(Notice{Kind: NoticeFriendRequested, Account: "bob"})
	hub.Publish(Notice{Kind: NoticeInvitation, Account: "bob"})
	hub.Publish(Notice{Kind: NoticePresence, Account: "bob"})
	hub.Publish(Notice{Kind: NoticeAnswer, Account: "bob"})
	hub.Publish(Notice{Kind: NoticeInvitation, Account: "carol"}) // offline: nothing to push to
	hub.Publish(Notice{Kind: NoticeRevoked, Account: "bob"})      // not a push
	want := []Push{{xB, PendingList1}, {xB, PendingInvite}, {xB, PendingPresent}, {xB, PendingAnswer}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v", i, got[i])
		}
	}
}
