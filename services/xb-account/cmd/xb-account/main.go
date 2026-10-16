// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-account/internal/adapter"
	"openpak/xb-live/services/xb-account/internal/api"
	"openpak/xb-live/services/xb-account/internal/core"
	"openpak/xb-live/services/xb-account/internal/enrol"
	"openpak/xb-live/services/xb-account/internal/provision"
	"openpak/xb-live/services/xb-account/internal/resolver"
	"openpak/xb-live/services/xb-account/internal/revoke"
	"openpak/xb-live/services/xb-account/internal/store"
	"openpak/xb-live/services/xb-account/internal/svc5"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

func required(name string) string {
	value := os.Getenv(name)
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}
func readSecret(name string) string {
	data, err := os.ReadFile(required(name))
	if err != nil {
		log.Fatalf("cannot read %s", name)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		log.Fatalf("%s is empty", name)
	}
	return value
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	// The dedicated client CA and workload URI checks authorize only Xbox callers.
	roots, err := os.ReadFile(required("XB_CLIENT_CA_FILE"))
	if err != nil {
		return fmt.Errorf("cannot read client CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(roots) {
		return fmt.Errorf("invalid client CA")
	}
	cfg := workloadTLS(pool)
	coreAddr := required("XB_CORE_ADDR")
	var transport credentials.TransportCredentials
	if caFile := os.Getenv("XB_CORE_CA_FILE"); caFile != "" {
		transport, err = credentials.NewClientTLSFromFile(caFile, os.Getenv("XB_CORE_SERVER_NAME"))
		if err != nil {
			return fmt.Errorf("invalid core TLS configuration")
		}
	} else {
		// Explicitly allow plaintext only on the existing private container network.
		if os.Getenv("XB_CORE_PLAINTEXT_INTERNAL") != "1" {
			return fmt.Errorf("core TLS required; private container deployments must explicitly set XB_CORE_PLAINTEXT_INTERNAL=1")
		}
		transport = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(coreAddr, grpc.WithTransportCredentials(transport))
	if err != nil {
		return fmt.Errorf("cannot configure core client")
	}
	defer conn.Close()
	coreKey := readSecret("XB_CORE_KEY_FILE")
	pepper, err := hex.DecodeString(readSecret("XB_PEPPER_FILE"))
	if err != nil {
		return fmt.Errorf("XB_PEPPER_FILE must contain hex")
	}
	db, err := store.Open(required("XB_DB_PATH"), pepper)
	if err != nil {
		return fmt.Errorf("cannot open store: %w", err)
	}
	defer db.Close()
	coreAPI := core.New(conn, coreKey)
	res := &resolver.Resolver{Core: coreAPI, Store: db}
	prov := &provision.Provisioner{Core: coreAPI, Store: db}
	vouchers := &voucher.Service{Core: coreAPI, Store: db}
	enrolments := &enrol.Service{Core: coreAPI, Store: db, Vouchers: vouchers}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go (&revoke.Processor{Core: coreAPI, Store: db}).Run(ctx, 2*time.Second)
	go func() {
		for ctx.Err() == nil {
			prov.Reap(ctx)
			enrolments.Reap(ctx)
			select {
			case <-ctx.Done():
			case <-time.After(time.Minute):
			}
		}
	}()
	mux := http.NewServeMux()
	legacy := api.Only(adapter.Handler(adapter.NewCore(conn, coreKey)), api.Auth, api.Gateway)
	mux.Handle("/internal/v1/resolve", legacy)
	mux.Handle("/livez", legacy)
	mux.Handle("/", api.HandlerFull(res, res, res, prov, enrolments, vouchers))
	handler := http.Handler(mux)
	addr := required("XB_LISTEN_ADDR")
	server := &http.Server{Addr: addr, Handler: handler, TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	cert, key := required("XB_TLS_CERT_FILE"), required("XB_TLS_KEY_FILE")
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS(cert, key) }()
	// Optional native service 5 (account signup requests) for the gateway.
	// Its names are held and checked against this service's own state.
	if addr := os.Getenv("XB_SVC5_ADDR"); addr != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return fmt.Errorf("service 5 TLS: %w", err)
		}
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: pool,
			ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13})), grpc.MaxRecvMsgSize(256<<10))
		allowOwner := os.Getenv("XB_SVC5_TEST_ALLOW_OWNER") == "1"
		if allowOwner {
			log.Printf("WARNING: XB_SVC5_TEST_ALLOW_OWNER=1: test deployment, one-user-per-account refusal disabled")
		}
		xbfeature.Register(g, &svc5.Server{Names: db, AllowOwner: allowOwner})
		go func() { done <- g.Serve(lis) }()
		defer g.Stop()
		log.Printf("xb-account service 5 (reservename only) on %s", lis.Addr())
	}
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}

func workloadTLS(pool *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 {
				return errors.New("unverified caller")
			}
			for _, uri := range state.PeerCertificates[0].URIs {
				// Per-route authorization (internal/api) narrows this further.
				if u := uri.String(); u == api.Auth || u == api.Gateway || u == api.Provisioner || u == api.Enroll {
					return nil
				}
			}
			return errors.New("unauthorized caller")
		},
	}
}
