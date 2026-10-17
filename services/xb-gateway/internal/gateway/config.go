// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config separates where the gateway binds from what it tells consoles: on the
// secondary host the public IP is NAT-ed and not a local address.
type Config struct {
	BindAddr      netip.AddrPort // local interface, e.g. 0.0.0.0:3074
	AdvertiseIP   netip.Addr     // public IPv4 baked into tickets; never a ZeroTier address
	HealthAddr    string         // loopback by default
	MaxSessions   int
	MaxPerIP      int
	InitRate      float64 // init packets per second per source IP
	InitBurst     float64
	InitWorkers   int
	PacketRate    float64 // per-session packets per second
	PacketBurst   float64
	IdleTimeout   time.Duration
	MaxLifetime   time.Duration
	ClockSkew     time.Duration
	DirectoryWait time.Duration
	MaxTCPPerSess int

	MinTicketStart time.Time // tickets issued before this are refused so consoles fetch new ones (zero = off)
	DebugFrames    bool      // off by default; logs per-frame metadata and a short hex prefix of TCP data
	DebugCapture   bool      // off by default; writes decrypted payloads
	CaptureDir     string    // required when DebugCapture
	CaptureMax     int64
}

func DefaultConfig() Config {
	return Config{
		BindAddr: netip.MustParseAddrPort("0.0.0.0:3074"), HealthAddr: "127.0.0.1:3075",
		MaxSessions: 4096, MaxPerIP: 8, InitRate: 2, InitBurst: 5, InitWorkers: 16,
		PacketRate: 300, PacketBurst: 600, IdleTimeout: 60 * time.Second, MaxLifetime: 8 * time.Hour,
		ClockSkew: 5 * time.Minute, DirectoryWait: 3 * time.Second, MaxTCPPerSess: 16, CaptureMax: 64 << 20,
	}
}

func (c Config) Validate() error {
	if !c.AdvertiseIP.Is4() || c.AdvertiseIP.IsUnspecified() || c.AdvertiseIP.IsLoopback() {
		return errors.New("XBGW_ADVERTISE_IP must be the public IPv4 address consoles reach")
	}
	if c.AdvertiseIP.IsPrivate() {
		return errors.New("XBGW_ADVERTISE_IP is private; advertise the public address, not a ZeroTier or LAN one")
	}
	if !c.BindAddr.IsValid() {
		return errors.New("invalid XBGW_BIND")
	}
	if c.MaxSessions < 1 || c.MaxPerIP < 1 || c.InitWorkers < 1 || c.MaxTCPPerSess < 1 || c.InitRate <= 0 || c.PacketRate <= 0 {
		return errors.New("limits must be positive")
	}
	if c.DebugCapture {
		if c.CaptureDir == "" {
			return errors.New("XBGW_DEBUG_CAPTURE requires XBGW_CAPTURE_DIR")
		}
		if abs, err := filepath.Abs(c.CaptureDir); err != nil || abs == "/tmp" || strings.HasPrefix(abs, "/tmp/") {
			return errors.New("capture directory must not be on the shared RAM disk")
		}
	}
	return nil
}

// ConfigFromEnv reads XBGW_* variables. lookup is os.LookupEnv in production.
func ConfigFromEnv(lookup func(string) (string, bool)) (Config, error) {
	c := DefaultConfig()
	var errs []error
	get := func(k string, f func(string) error) {
		if v, ok := lookup(k); ok && v != "" {
			if err := f(v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", k, err))
			}
		}
	}
	integer := func(dst *int) func(string) error {
		return func(v string) (err error) { *dst, err = strconv.Atoi(v); return }
	}
	float := func(dst *float64) func(string) error {
		return func(v string) (err error) { *dst, err = strconv.ParseFloat(v, 64); return }
	}
	dur := func(dst *time.Duration) func(string) error {
		return func(v string) (err error) { *dst, err = time.ParseDuration(v); return }
	}
	get("XBGW_BIND", func(v string) (err error) { c.BindAddr, err = netip.ParseAddrPort(v); return })
	get("XBGW_ADVERTISE_IP", func(v string) (err error) { c.AdvertiseIP, err = netip.ParseAddr(v); return })
	get("XBGW_HEALTH_ADDR", func(v string) error { c.HealthAddr = v; return nil })
	get("XBGW_MAX_SESSIONS", integer(&c.MaxSessions))
	get("XBGW_MAX_SESSIONS_PER_IP", integer(&c.MaxPerIP))
	get("XBGW_INIT_WORKERS", integer(&c.InitWorkers))
	get("XBGW_INIT_RATE_PER_IP", float(&c.InitRate))
	get("XBGW_PACKET_RATE", float(&c.PacketRate))
	get("XBGW_IDLE_TIMEOUT", dur(&c.IdleTimeout))
	get("XBGW_MAX_LIFETIME", dur(&c.MaxLifetime))
	get("XBGW_MIN_TICKET_START", func(v string) (err error) { c.MinTicketStart, err = time.Parse(time.RFC3339, v); return })
	get("XBGW_DEBUG_FRAMES", func(v string) (err error) { c.DebugFrames, err = strconv.ParseBool(v); return })
	get("XBGW_DEBUG_CAPTURE", func(v string) (err error) { c.DebugCapture, err = strconv.ParseBool(v); return })
	get("XBGW_CAPTURE_DIR", func(v string) error { c.CaptureDir = v; return nil })
	if err := errors.Join(errs...); err != nil {
		return c, err
	}
	c.InitBurst, c.PacketBurst = max(c.InitBurst, c.InitRate*2.5), max(c.PacketBurst, c.PacketRate*2)
	return c, c.Validate()
}
