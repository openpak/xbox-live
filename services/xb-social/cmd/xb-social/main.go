// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"net"
	"path/filepath"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-social/internal/core"
	"openpak/xb-live/services/xb-social/internal/friends"
	"openpak/xb-live/services/xb-social/internal/social"
	"openpak/xb-live/services/xb-social/internal/svc1"
)

const gatewayID = "spiffe://openpak/xb-gateway"

func required(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}

func pool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid CA bundle")
	}
	return p, nil
}

// Handler serves the friends projection to the gateway. The viewer XUID comes
// from the gateway's authenticated connection context, never from the client.
func Handler(s *friends.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/friends", func(w http.ResponseWriter, r *http.Request) {
		if !fromGateway(r.TLS) {
			http.Error(w, "forbidden", 403)
			return
		}
		list, err := s.Friends(r.Context(), r.URL.Query().Get("viewer"))
		switch {
		case errors.Is(err, friends.ErrDenied):
			http.Error(w, "forbidden", 403)
		case err != nil:
			http.Error(w, "unavailable", 503)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			json.NewEncoder(w).Encode(list)
		}
	})
	return mux
}

func fromGateway(s *tls.ConnectionState) bool {
	if s == nil || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
		return false
	}
	for _, u := range s.PeerCertificates[0].URIs {
		if u.String() == gatewayID {
			return true
		}
	}
	return false
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	clientCA, err := pool(required("XB_CLIENT_CA_FILE"))
	if err != nil {
		return fmt.Errorf("client CA: %w", err)
	}
	accountCA, err := pool(required("XB_ACCOUNT_CA_FILE"))
	if err != nil {
		return fmt.Errorf("account CA: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(required("XB_TLS_CERT_FILE"), required("XB_TLS_KEY_FILE"))
	if err != nil {
		return errors.New("cannot load workload certificate")
	}
	keyBytes, err := os.ReadFile(required("XB_CORE_KEY_FILE"))
	if err != nil || strings.TrimSpace(string(keyBytes)) == "" {
		return errors.New("cannot read core key")
	}
	var transport credentials.TransportCredentials
	if ca := os.Getenv("XB_CORE_CA_FILE"); ca != "" {
		if transport, err = credentials.NewClientTLSFromFile(ca, os.Getenv("XB_CORE_SERVER_NAME")); err != nil {
			return errors.New("invalid core TLS configuration")
		}
	} else if os.Getenv("XB_CORE_PLAINTEXT_INTERNAL") == "1" {
		transport = insecure.NewCredentials()
	} else {
		return errors.New("core TLS required; set XB_CORE_PLAINTEXT_INTERNAL=1 only on the private container network")
	}
	conn, err := grpc.NewClient(required("XB_CORE_ADDR"), grpc.WithTransportCredentials(transport))
	if err != nil {
		return errors.New("cannot configure core client")
	}
	defer conn.Close()
	accounts := &xbaccountapi.Client{Base: required("XB_ACCOUNT_URL"), HTTP: &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: accountCA, Certificates: []tls.Certificate{cert}}},
	}}
	backend := core.New(conn, strings.TrimSpace(string(keyBytes)))
	svc := &friends.Service{Core: backend, Resolver: accounts}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	var gsrv *grpc.Server
	if addr := os.Getenv("XB_FEATURE_ADDR"); addr != "" {
		var err error
		if gsrv, err = startFeature(ctx, addr, backend, accounts, clientCA, cert); err != nil {
			return err
		}
		defer gsrv.Stop()
	}
	srv := &http.Server{Addr: required("XB_LISTEN_ADDR"), Handler: Handler(svc), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientCAs: clientCA, ClientAuth: tls.RequireAndVerifyClientCert, Certificates: []tls.Certificate{cert}}}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(sd)
}

// startFeature serves the native presence/social service ids to the gateway
// (xbfeature stream over mTLS) and runs the presence keepalive and the core
// event poller behind it.
func startFeature(ctx context.Context, addr string, backend core.Backend, accounts xbaccountapi.Resolver, clientCA *x509.CertPool, cert tls.Certificate) (*grpc.Server, error) {
	ttl := social.DefaultTTL
	if v := os.Getenv("XB_PRESENCE_TTL_SECS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, errors.New("XB_PRESENCE_TTL_SECS must be a positive number")
		}
		ttl = time.Duration(n) * time.Second
	}
	presence := &social.Presences{Core: backend}
	hub := &social.Hub{}
	soc := &social.Service{Core: backend, Resolver: accounts, Presence: presence, Hub: hub}
	srv := &svc1.Server{Social: soc, Presence: presence, TTL: ttl, OfflineOnClose: os.Getenv("XB_PRESENCE_OFFLINE_ON_CLOSE") == "1"}
	// Friend/invite operations, the notification poll and AliveReply lists are
	// built in (docs/xbox/social-protocol.md). Messaging (service 18) and the
	// gateway UDP push (social.PushSource -> 0x5309) are not wired: no push
	// channel to the gateway exists yet, so the console only learns of changes
	// when it polls.
	stateDir := os.Getenv("XB_STATE_DIR")
	if stateDir == "" {
		stateDir = "/var/lib/xb-social"
	}
	poller := &social.Poller{Core: backend, Cursor: social.FileCursor{Path: filepath.Join(stateDir, "events.cursor")},
		Hub: hub, Presence: presence}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("feature listener: %w", err)
	}
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: clientCA,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13})), grpc.MaxRecvMsgSize(256<<10))
	xbfeature.Register(g, xbfeature.LogHTTP(srv))
	go func() {
		if err := g.Serve(lis); err != nil {
			log.Printf("feature server: %v", err)
		}
	}()
	go presence.Run(ctx, 10*time.Second)
	go poller.Run(ctx)
	return g, nil
}
