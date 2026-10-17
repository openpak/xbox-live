// SPDX-License-Identifier: AGPL-3.0-only

package friends

import (
	"context"
	"errors"
	"sync"
	"testing"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-social/internal/core"
)

type fakeCore struct {
	mu       sync.Mutex
	friends  map[string][]core.Friend
	links    map[string]core.Link
	presence []core.Presence
	blocked  map[string]bool
	failOp   string
	asked    []string
}

func (f *fakeCore) err(op string) error {
	if f.failOp == op {
		return core.ErrUnavailable
	}
	return nil
}
func (f *fakeCore) ListFriends(_ context.Context, a string) ([]core.Friend, error) {
	return f.friends[a], f.err("friends")
}
func (f *fakeCore) ActiveLink(_ context.Context, a string) (core.Link, error) {
	if e := f.err("link:" + a); e != nil {
		return core.Link{}, e
	}
	if l, ok := f.links[a]; ok {
		return l, nil
	}
	return core.Link{}, core.ErrNotFound
}
func (f *fakeCore) GetPresence(_ context.Context, ids []string) ([]core.Presence, error) {
	f.mu.Lock()
	f.asked = append(f.asked, ids...)
	f.mu.Unlock()
	return f.presence, f.err("presence")
}
func (f *fakeCore) CanDiscover(_ context.Context, _, t string) (bool, error) {
	return !f.blocked[t], f.err("check")
}

type fakeRes struct{ err error }

func (r fakeRes) ResolveUser(_ context.Context, x string) (xbaccountapi.Principal, error) {
	if r.err != nil {
		return xbaccountapi.Principal{}, r.err
	}
	return xbaccountapi.Principal{Kind: xbaccountapi.KindUser, PrincipalID: x, CoreAccountID: "me", Status: xbaccountapi.StatusActive}, nil
}
func (fakeRes) ResolveGamertag(context.Context, string) (xbaccountapi.Principal, error) {
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}
func (fakeRes) ResolveDevice(context.Context, string) (xbaccountapi.Principal, error) {
	return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
}

const viewer = "0009000000000001"

func fixture() *fakeCore {
	return &fakeCore{
		friends: map[string][]core.Friend{"me": {
			{AccountID: "a", DisplayName: "Alice Display", Since: 100, LastSeen: 200},
			{AccountID: "b", DisplayName: "Bob Display"},
			{AccountID: "c", DisplayName: "Carol Display"},
			{AccountID: "d", DisplayName: "Dave Display"},
			{AccountID: "e", DisplayName: "Eve Display"},
		}},
		links: map[string]core.Link{
			"a": {SubjectID: "0009000000000010", PublicCode: "Alice"},
			"b": {SubjectID: "0009000000000020", PublicCode: "Bob"},
			"c": {SubjectID: "0009000000000030", PublicCode: ""},    // no gamertag published
			"e": {SubjectID: "0009000000000050", PublicCode: "Eve"}, // blocked: offline
		},
		blocked: map[string]bool{"e": true},
		presence: []core.Presence{
			{AccountID: "a", Namespace: "xbox", TitleID: "4d530004", SinceUnix: 300},
			{AccountID: "b", Namespace: "switch", TitleID: "0100abcd", SinceUnix: 400},
			{AccountID: "e", Namespace: "xbox", TitleID: "4d530004"},
			{AccountID: "stranger", Namespace: "xbox", TitleID: "x"},
		},
	}
}

func svc(c *fakeCore, r xbaccountapi.Resolver) *Service { return &Service{Core: c, Resolver: r} }

func TestFriendsProjectOnlyRealIdentities(t *testing.T) {
	c := fixture()
	l, err := svc(c, fakeRes{}).Friends(context.Background(), viewer)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Friends) != 3 || l.Omitted != 2 { // c has no gamertag, d has no Xbox link
		t.Fatalf("%+v", l)
	}
	a, b, e := l.Friends[0], l.Friends[1], l.Friends[2]
	if a.XUID != "0009000000000010" || a.Gamertag != "Alice" || a.FriendsSince != 100 || a.LastSeen != 200 ||
		a.Presence != (Presence{Online, "4d530004", 300}) {
		t.Fatalf("alice %+v", a)
	}
	if b.Presence.State != Online || b.Presence.TitleID != "" {
		t.Fatalf("other-platform friend must be online without an Xbox title: %+v", b)
	}
	if e.Presence.State != Offline || e.Presence.TitleID != "" {
		t.Fatalf("blocked friend leaked presence: %+v", e)
	}
	for _, f := range l.Friends {
		if f.Gamertag == "Alice Display" || f.Gamertag == "Bob Display" {
			t.Fatal("gamertag derived from display name")
		}
	}
	for _, id := range c.asked {
		if id == "e" || id == "stranger" {
			t.Fatalf("asked core for presence of %q", id)
		}
	}
}

func TestOfflineWhenNoSession(t *testing.T) {
	c := fixture()
	c.presence = nil
	l, _ := svc(c, fakeRes{}).Friends(context.Background(), viewer)
	for _, f := range l.Friends {
		if f.Presence.State != Offline {
			t.Fatalf("%+v", f)
		}
	}
}

func TestViewerAdmission(t *testing.T) {
	for _, err := range []error{&xbaccountapi.DeniedError{Principal: xbaccountapi.Principal{Status: xbaccountapi.StatusBanned}}, xbaccountapi.ErrNotFound, xbaccountapi.ErrInvalid} {
		if _, e := svc(fixture(), fakeRes{err}).Friends(context.Background(), viewer); !errors.Is(e, ErrDenied) {
			t.Fatalf("%v: %v", err, e)
		}
	}
	if _, e := svc(fixture(), fakeRes{xbaccountapi.ErrUnavailable}).Friends(context.Background(), viewer); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
}

// Regression (live 503): one friend whose link cannot be read must not fail the
// whole list; presence and discovery checks are a best-effort overlay.
func TestOneBadFriendOrPresenceFailureStillAnswers(t *testing.T) {
	c := fixture()
	c.failOp = "link:b"
	l, err := svc(c, fakeRes{}).Friends(context.Background(), viewer)
	if err != nil || len(l.Friends) != 2 || l.Omitted != 3 { // a, e listed; b (failed), c, d omitted
		t.Fatalf("bad link: %+v %v", l, err)
	}
	for _, op := range []string{"check", "presence"} {
		c := fixture()
		c.failOp = op
		l, err := svc(c, fakeRes{}).Friends(context.Background(), viewer)
		if err != nil || len(l.Friends) != 3 {
			t.Fatalf("%s: %+v %v", op, l, err)
		}
		for _, f := range l.Friends {
			if f.Presence.State != Offline {
				t.Fatalf("%s: %+v shown online without data", op, f)
			}
		}
	}
}

func TestBackendOutageIsNotAPartialList(t *testing.T) {
	c := fixture()
	c.failOp = "friends"
	if l, err := svc(c, fakeRes{}).Friends(context.Background(), viewer); !errors.Is(err, ErrUnavailable) || len(l.Friends) != 0 {
		t.Fatalf("%+v %v", l, err)
	}
}

func TestPresenceRestrictedToFriends(t *testing.T) {
	got, err := svc(fixture(), fakeRes{}).Presence(context.Background(), viewer, []string{"0009000000000010", "0009000000000999"})
	if err != nil || len(got) != 1 || got[0].XUID != "0009000000000010" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestConcurrentCallsRace(t *testing.T) {
	s := svc(fixture(), fakeRes{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Friends(context.Background(), viewer); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
