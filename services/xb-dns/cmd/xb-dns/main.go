// SPDX-License-Identifier: AGPL-3.0-only
// xb-dns: exact-name Xbox discovery DNS. Not a resolver; the established
// OpenPak resolver forwards the Xbox names here.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	"openpak/xb-live/services/xb-dns/internal/xbdns"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	health := env("XBDNS_HEALTH", "127.0.0.1:5354")
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		r, err := http.Get("http://" + health + "/healthz")
		if err != nil || r.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	t, err := xbdns.BuildTable(os.Getenv("XBDNS_AUTH_IP"), os.Getenv("XBDNS_TABLE_FILE"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	rate, _ := strconv.ParseFloat(env("XBDNS_RATE", "20"), 64)
	burst, _ := strconv.ParseFloat(env("XBDNS_BURST", "40"), 64)
	s := &xbdns.Server{Table: t, Lim: xbdns.NewLimiter(rate, burst, 4096)}
	// Default binds loopback high port only; public :53 must be set explicitly.
	conn, err := net.ListenPacket("udp", env("XBDNS_BIND", "127.0.0.1:5353"))
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		c := &s.C
		fmt.Fprintf(w, "queries %d\nanswered %d\nnxdomain %d\nrefused %d\nformerr %d\ndropped %d\nrate_limited %d\n",
			c.Queries.Load(), c.Answered.Load(), c.NXDomain.Load(), c.Refused.Load(), c.FormErr.Load(), c.Dropped.Load(), c.RateLimited.Load())
	})
	go func() { log.Fatal(http.ListenAndServe(health, mux)) }()
	log.Printf("xb-dns up: %s, %d names", conn.LocalAddr(), len(t))
	log.Fatal(s.Serve(conn))
}
