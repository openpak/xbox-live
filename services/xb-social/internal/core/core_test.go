// SPDX-License-Identifier: AGPL-3.0-only

package core

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	pb "openpak/xb-live/services/xb-social/internal/corepb"
)

type fake struct {
	pb.UnimplementedSocialServer
	pb.UnimplementedSessionsServer
	pb.UnimplementedLinksServer
	presenceCalls []int
}

func auth(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("authorization"); len(v) != 1 || v[0] != "Bearer k" {
		return status.Error(codes.Unauthenticated, "no")
	}
	return nil
}
func (f *fake) ListFriends(ctx context.Context, r *pb.ListFriendsRequest) (*pb.ListFriendsResponse, error) {
	if err := auth(ctx); err != nil {
		return nil, err
	}
	return &pb.ListFriendsResponse{Friends: []*pb.Friend{{AccountId: "a", DisplayName: "A", LastSeenUnix: 5, FriendsSinceUnix: 6}}}, nil
}
func (f *fake) GetActiveLinkByAccount(ctx context.Context, r *pb.GetActiveLinkByAccountRequest) (*pb.GetLinkBySubjectResponse, error) {
	if err := auth(ctx); err != nil {
		return nil, err
	}
	if r.Namespace != "xbox" {
		return nil, status.Error(codes.NotFound, "ns")
	}
	switch r.AccountId {
	case "a":
		return &pb.GetLinkBySubjectResponse{AccountId: "a", State: pb.LinkState_LINK_STATE_ACTIVE, SubjectId: "0009000000000010", PublicCode: "Alice"}, nil
	case "pending":
		return &pb.GetLinkBySubjectResponse{AccountId: "pending", State: pb.LinkState_LINK_STATE_PENDING, SubjectId: "0009000000000011"}, nil
	}
	return nil, status.Error(codes.NotFound, "none")
}
func (f *fake) GetPresence(ctx context.Context, r *pb.GetPresenceRequest) (*pb.GetPresenceResponse, error) {
	if err := auth(ctx); err != nil {
		return nil, err
	}
	f.presenceCalls = append(f.presenceCalls, len(r.AccountIds))
	return &pb.GetPresenceResponse{Presence: []*pb.Presence{{AccountId: r.AccountIds[0], Namespace: "xbox", TitleId: "t", SinceUnix: 9}}}, nil
}
func (f *fake) CheckInteraction(ctx context.Context, r *pb.CheckInteractionRequest) (*pb.CheckInteractionResponse, error) {
	if r.Kind != pb.InteractionKind_INTERACTION_KIND_DISCOVER {
		return nil, status.Error(codes.InvalidArgument, "kind")
	}
	return &pb.CheckInteractionResponse{Allowed: r.TargetId != "blocked"}, nil
}

func dial(t *testing.T, key string) (*Client, *fake) {
	t.Helper()
	l := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	f := &fake{}
	pb.RegisterSocialServer(s, f)
	pb.RegisterSessionsServer(s, f)
	pb.RegisterLinksServer(s, f)
	go s.Serve(l)
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient("passthrough:///x", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return l.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return New(conn, key), f
}

func TestClientAgainstFakeCore(t *testing.T) {
	c, f := dial(t, "k")
	ctx := context.Background()
	fr, err := c.ListFriends(ctx, "me")
	if err != nil || len(fr) != 1 || fr[0] != (Friend{"a", "A", 5, 6}) {
		t.Fatalf("%+v %v", fr, err)
	}
	if l, err := c.ActiveLink(ctx, "a"); err != nil || l != (Link{"0009000000000010", "Alice"}) {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := c.ActiveLink(ctx, "zzz"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := c.ActiveLink(ctx, "pending"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pending link must not count: %v", err)
	}
	if ok, err := c.CanDiscover(ctx, "me", "a"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := c.CanDiscover(ctx, "me", "blocked"); ok {
		t.Fatal("blocked allowed")
	}
	ids := make([]string, 450)
	for i := range ids {
		ids[i] = "x"
	}
	p, err := c.GetPresence(ctx, ids)
	if err != nil || len(p) != 3 || len(f.presenceCalls) != 3 || f.presenceCalls[0] != 200 || f.presenceCalls[2] != 50 {
		t.Fatalf("%+v %v %v", p, err, f.presenceCalls)
	}
}

func TestWrongCoreKeyIsUnavailable(t *testing.T) {
	c, _ := dial(t, "wrong")
	if _, err := c.ListFriends(context.Background(), "me"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
