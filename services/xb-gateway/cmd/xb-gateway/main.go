// SPDX-License-Identifier: AGPL-3.0-only

// xb-gateway terminates the native Xbox security-gateway protocol (UDP 3074).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-gateway/internal/gateway"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("xb-gateway failed", "err", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := gateway.ConfigFromEnv(os.LookupEnv)
	if err != nil {
		return err
	}
	files := gateway.MTLSFiles{Cert: os.Getenv("XBGW_MTLS_CERT"), Key: os.Getenv("XBGW_MTLS_KEY"), CA: os.Getenv("XBGW_MTLS_CA")}

	var dir gateway.Directory
	var revocations xbaccountapi.Revocations
	if base := os.Getenv("XBGW_ACCOUNT_URL"); base != "" {
		if !strings.HasPrefix(base, "https://") {
			return fmt.Errorf("XBGW_ACCOUNT_URL must be https (mutual TLS)")
		}
		cert, err := tls.LoadX509KeyPair(files.Cert, files.Key)
		if err != nil {
			return fmt.Errorf("mTLS client identity: %w", err)
		}
		ca, err := os.ReadFile(files.CA)
		if err != nil {
			return fmt.Errorf("mTLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return fmt.Errorf("mTLS CA bundle empty")
		}
		client := &xbaccountapi.Client{Base: base, HTTP: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13,
				ServerName: os.Getenv("XBGW_ACCOUNT_SERVER_NAME")}}}}
		dir, revocations = gateway.AccountDirectory{Resolver: client}, client
	}

	backends := map[uint32]gateway.Backend{}
	for _, item := range strings.Fields(strings.ReplaceAll(os.Getenv("XBGW_BACKENDS"), ",", " ")) {
		idStr, target, ok := strings.Cut(item, "=")
		id, err := strconv.ParseUint(idStr, 10, 32)
		if !ok || err != nil || target == "" {
			return fmt.Errorf("XBGW_BACKENDS entry %q must be <service id>=<host:port>", item)
		}
		opt, err := files.DialOption()
		if err != nil {
			return fmt.Errorf("backend mTLS: %w", err)
		}
		b, err := gateway.NewGRPCBackend(target, opt)
		if err != nil {
			return err
		}
		backends[uint32(id)] = b
	}

	// Ticket verification uses the SG keyring shared with xb-auth (same file
	// format and rotation ids). Without it the gateway is not ready and rejects every init.
	var verifier gateway.TicketVerifier
	if path := os.Getenv("XBGW_SG_KEYRING_FILE"); path != "" {
		ring, err := krb.LoadKeyring(path, 16)
		if err != nil {
			return fmt.Errorf("XBGW_SG_KEYRING_FILE: %w", err)
		}
		verifier = gateway.KrbVerifier{SGKeys: ring}
	} else {
		log.Warn("XBGW_SG_KEYRING_FILE not set: all handshakes will be rejected")
	}

	srv, err := gateway.NewServer(cfg, log, verifier, dir, backends)
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	health := &http.Server{Addr: cfg.HealthAddr, Handler: srv.HealthHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := health.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("health listener", "err", err.Error())
		}
	}()
	if revocations != nil {
		go srv.FollowRevocations(ctx, revocations)
	}
	log.Info("xb-gateway listening", "bind", srv.Addr().String(), "advertise", cfg.AdvertiseIP.String())
	err = srv.Serve(ctx)
	health.Shutdown(context.Background())
	return err
}

// healthcheck is the container HEALTHCHECK: listener liveness only. Readiness
// (dependencies) and end-to-end state are on /readyz and /healthz for operators.
func healthcheck() int {
	addr := os.Getenv("XBGW_HEALTH_ADDR")
	if addr == "" {
		addr = gateway.DefaultConfig().HealthAddr
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/livez")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
