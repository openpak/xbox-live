// SPDX-License-Identifier: AGPL-3.0-only

// Command xb-enroll is the public device-pairing front. See internal/server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"openpak/xb-live/internal/xbenrolapi"
	"openpak/xb-live/services/xb-enroll/internal/server"
)

func required(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func listenAddr() string {
	if a := os.Getenv("XBE_LISTEN_ADDR"); a != "" {
		return a
	}
	return "0.0.0.0:8080"
}

// healthcheck is for the container HealthCmd (the scratch image has no tools).
func healthcheck() int {
	addr := listenAddr()
	if strings.HasPrefix(addr, "0.0.0.0") || strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1:" + addr[strings.LastIndex(addr, ":")+1:]
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func run() error {
	cert, err := tls.LoadX509KeyPair(required("XBE_CLIENT_CERT_FILE"), required("XBE_CLIENT_KEY_FILE"))
	if err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(required("XBE_ACCOUNT_CA_FILE"))
	if err != nil {
		return fmt.Errorf("account CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid account CA")
	}
	var proxies []netip.Prefix
	for _, p := range strings.Split(os.Getenv("XBE_TRUSTED_PROXIES"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			pf, err := netip.ParsePrefix(p)
			if err != nil {
				return fmt.Errorf("XBE_TRUSTED_PROXIES: %w", err)
			}
			proxies = append(proxies, pf)
		}
	}
	backend := &xbenrolapi.Client{Base: required("XBE_ACCOUNT_URL"), HTTP: &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: os.Getenv("XBE_ACCOUNT_SERVER_NAME")},
		MaxIdleConns:    8, IdleConnTimeout: 30 * time.Second}}}
	srv := &http.Server{Addr: listenAddr(), Handler: server.New(server.Config{Backend: backend, TrustedProxies: proxies}).Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	log.Printf("xb-enroll listening on %s (plain HTTP; terminate TLS in front)", srv.Addr)
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(sd)
}
