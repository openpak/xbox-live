package adapter

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
)

type fakeCore struct {
	pb.UnimplementedLinksServer
	pb.UnimplementedIdentityServer
	state         pb.LinkState
	accountStatus pb.AccountStatus
	subject       string
	unavailable   bool
	revoked       bool
}

func (f *fakeCore) check(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if values := md.Get("authorization"); len(values) != 1 || values[0] != "Bearer test-key" {
		return status.Error(codes.Unauthenticated, "missing auth")
	}
	if f.unavailable {
		return status.Error(codes.Unavailable, "backend failure")
	}
	return nil
}
func (f *fakeCore) GetLinkByPublicCode(ctx context.Context, r *pb.GetLinkByPublicCodeRequest) (*pb.GetLinkBySubjectResponse, error) {
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	if r.Namespace != "xbox" || r.PublicCode != "Player One" {
		return nil, status.Error(codes.NotFound, "unknown")
	}
	return &pb.GetLinkBySubjectResponse{LinkId: "link", AccountId: "account", SubjectId: f.subject, State: f.state}, nil
}
func (f *fakeCore) GetLinkBySubject(ctx context.Context, r *pb.GetLinkBySubjectRequest) (*pb.GetLinkBySubjectResponse, error) {
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	if f.revoked || r.Namespace != "xbox" || r.SubjectId != f.subject {
		return nil, status.Error(codes.NotFound, "revoked")
	}
	return &pb.GetLinkBySubjectResponse{LinkId: "link", AccountId: "account", State: f.state}, nil
}
func (f *fakeCore) GetAccount(ctx context.Context, r *pb.GetAccountRequest) (*pb.GetAccountResponse, error) {
	if err := f.check(ctx); err != nil {
		return nil, err
	}
	if r.AccountId != "account" {
		return nil, status.Error(codes.NotFound, "unknown")
	}
	return &pb.GetAccountResponse{AccountId: "account", Status: f.accountStatus, DisplayName: "Player One", Email: "never-return@example.invalid"}, nil
}
func client(t *testing.T, f *fakeCore) *Core {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterLinksServer(server, f)
	pb.RegisterIdentityServer(server, f)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///core", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return NewCore(conn, "test-key")
}
func TestResolveCoreAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*fakeCore)
		want   error
	}{
		{"active", func(*fakeCore) {}, nil},
		{"pending", func(f *fakeCore) { f.state = pb.LinkState_LINK_STATE_PENDING }, ErrUnknown},
		{"banned", func(f *fakeCore) { f.accountStatus = pb.AccountStatus_ACCOUNT_STATUS_BANNED }, ErrDisabled},
		{"deleting", func(f *fakeCore) { f.accountStatus = pb.AccountStatus_ACCOUNT_STATUS_DELETION_PENDING }, ErrDisabled},
		{"unknown-status", func(f *fakeCore) { f.accountStatus = pb.AccountStatus_ACCOUNT_STATUS_UNSPECIFIED }, ErrDisabled},
		{"unavailable", func(f *fakeCore) { f.unavailable = true }, ErrUnavailable},
		{"unlink-during-resolution", func(f *fakeCore) { f.revoked = true }, ErrUnknown},
		{"invalid-subject", func(f *fakeCore) { f.subject = "not-an-xuid" }, ErrUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeCore{state: pb.LinkState_LINK_STATE_ACTIVE, accountStatus: pb.AccountStatus_ACCOUNT_STATUS_ACTIVE, subject: "0009000000000001"}
			test.change(f)
			result, err := client(t, f).Resolve(context.Background(), "Player One")
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v want %v", err, test.want)
			}
			if test.want == nil && (result.XUID != f.subject || result.AccountID != "account") {
				t.Fatalf("wrong projection: %+v", result)
			}
		})
	}
}
func TestResolveUnknownAndCancellation(t *testing.T) {
	f := &fakeCore{state: pb.LinkState_LINK_STATE_ACTIVE, accountStatus: pb.AccountStatus_ACCOUNT_STATUS_ACTIVE, subject: "0009000000000001"}
	c := client(t, f)
	if _, err := c.Resolve(context.Background(), "Other"); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Resolve(ctx, "Player One"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
func TestHTTPContract(t *testing.T) {
	f := &fakeCore{state: pb.LinkState_LINK_STATE_ACTIVE, accountStatus: pb.AccountStatus_ACCOUNT_STATUS_ACTIVE, subject: "0009000000000001"}
	handler := Handler(client(t, f))
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"gamertag":"Player One"}`, 200},
		{`{"gamertag":"Other"}`, 404},
		{`{"gamertag":"Player One","account_id":"attacker"}`, 400},
		{`{"gamertag":"Player One"} {}`, 400},
		{`{"gamertag":" Player One"}`, 400},
		{`{"gamertag":"` + strings.Repeat("a", 2048) + `"}`, 400},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("POST", "/internal/v1/resolve", strings.NewReader(tc.body)))
		if response.Code != tc.code {
			t.Fatalf("status %d want %d", response.Code, tc.code)
		}
		if strings.Contains(response.Body.String(), "email") {
			t.Fatal("private core fields leaked")
		}
	}
}
