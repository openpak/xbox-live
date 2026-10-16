// SPDX-License-Identifier: AGPL-3.0-only

// xb-tou serves native service 11 (Terms of Use content) to the gateway over
// mutual-TLS gRPC streams (internal/xbfeature).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-tou/internal/content"
	"openpak/xb-live/services/xb-tou/internal/tou"
)

func required(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cert, err := tls.LoadX509KeyPair(required("XB_TLS_CERT_FILE"), required("XB_TLS_KEY_FILE"))
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(required("XB_CLIENT_CA_FILE"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("invalid client CA bundle")
	}
	creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13})
	lis, err := net.Listen("tcp", required("XB_TOU_ADDR"))
	if err != nil {
		return err
	}
	s := grpc.NewServer(grpc.Creds(creds), grpc.MaxRecvMsgSize(256<<10))
	srv := &tou.Server{Root: os.Getenv("XB_TOU_CONTENT_DIR")}
	// XB_TOU_BUILTIN_COUNTRIES (comma-separated ISO codes, e.g. "US,IE")
	// enables the generated OpenPak content set; unset keeps operator-only.
	if v := os.Getenv("XB_TOU_BUILTIN_COUNTRIES"); v != "" {
		set, err := content.Build(strings.Split(v, ","))
		if err != nil {
			return err
		}
		srv.Builtin = set
		log.Printf("xb-tou built-in OpenPak content enabled for %s (%d files)", v, len(set))
	}
	xbfeature.Register(s, xbfeature.LogHTTP(srv))
	log.Printf("xb-tou listening on %s (content %q)", lis.Addr(), os.Getenv("XB_TOU_CONTENT_DIR"))
	return s.Serve(lis)
}
