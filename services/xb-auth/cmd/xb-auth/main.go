// SPDX-License-Identifier: AGPL-3.0-only
// xb-auth is the original Xbox Kerberos service: UDP 88 AS/TGS plus a private
// health listener. It holds the TGS, gateway-ticket and account-key secrets and
// asks xb-account (mutual TLS) who a gamertag is. It claims nothing about a
// console actually signing in; /readyz only says the listener is up.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-auth/internal/devicekeys"
	"openpak/xb-live/services/xb-auth/internal/kdc"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func accountClient(s *settings) (*http.Client, error) {
	u, err := url.Parse(s.accountURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("XB_ACCOUNT_URL must be an https URL")
	}
	ca, err := os.ReadFile(s.accountCA)
	if err != nil {
		return nil, errors.New("cannot read XB_ACCOUNT_CA_FILE")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid XB_ACCOUNT_CA_FILE")
	}
	cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
	if err != nil {
		return nil, errors.New("cannot load client certificate")
	}
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}},
		MaxIdleConnsPerHost: 8, IdleConnTimeout: 60 * time.Second,
	}}, nil
}

func run() error {
	s, err := loadSettings(os.Getenv)
	if err != nil {
		return err
	}
	hc, err := accountClient(s)
	if err != nil {
		return err
	}
	devices := devicekeys.None
	if s.deviceKeysFile != "" {
		if devices, err = devicekeys.Load(s.deviceKeysFile); err != nil {
			return err
		}
	}
	k, err := kdc.New(s.kdc, &xbaccountapi.Client{Base: s.accountURL, HTTP: hc}, devices)
	if err != nil {
		return err
	}
	conn, err := net.ListenPacket("udp", s.udpAddr)
	if err != nil {
		return fmt.Errorf("cannot bind UDP listener: %w", err)
	}
	ready := make(chan struct{})
	close(ready) // the socket is bound; Serve starts immediately below
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ready:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not ready", http.StatusServiceUnavailable)
		}
	})
	health := &http.Server{Addr: s.healthAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 2)
	go func() { errc <- (&kdc.Server{KDC: k, Conn: conn}).Serve(ctx) }()
	go func() {
		if err := health.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	log.Printf("xb-auth listening on udp %s, health %s, gateway %s", conn.LocalAddr(), s.healthAddr, s.kdc.GatewayIP)
	select {
	case err = <-errc:
	case <-ctx.Done():
	}
	stop()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	health.Shutdown(sctx)
	return err
}
