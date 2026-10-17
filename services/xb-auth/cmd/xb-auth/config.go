// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/services/xb-auth/internal/kdc"
)

type settings struct {
	kdc        kdc.Config
	udpAddr    string
	healthAddr string

	accountURL  string
	accountCA   string
	tlsCertFile string
	tlsKeyFile  string
}

func duration(get func(string) string, name string, def time.Duration) (time.Duration, error) {
	v := get(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return d, nil
}

// loadSettings reads the environment. Every secret is a file path; nothing
// secret is accepted inline, and no key has a built-in default.
func loadSettings(get func(string) string) (*settings, error) {
	req := func(name string) (string, error) {
		if v := get(name); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("%s is required", name)
	}
	s := &settings{kdc: kdc.DefaultConfig(), udpAddr: ":88", healthAddr: "127.0.0.1:8088"}
	if v := get("XB_AUTH_UDP_ADDR"); v != "" {
		s.udpAddr = v
	}
	if v := get("XB_AUTH_HEALTH_ADDR"); v != "" {
		s.healthAddr = v
	}
	if v := get("XB_GATEWAY_PUBLIC_IPV4"); v != "" {
		ip, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("XB_GATEWAY_PUBLIC_IPV4: %w", err)
		}
		s.kdc.GatewayIP = ip
	}
	var err error
	if s.kdc.TGTLifetime, err = duration(get, "XB_TGT_LIFETIME", s.kdc.TGTLifetime); err != nil {
		return nil, err
	}
	if s.kdc.TicketLifetime, err = duration(get, "XB_TICKET_LIFETIME", s.kdc.TicketLifetime); err != nil {
		return nil, err
	}
	if s.kdc.ClockSkew, err = duration(get, "XB_CLOCK_SKEW", s.kdc.ClockSkew); err != nil {
		return nil, err
	}
	if v := get("XB_USER_COUNTRY_ID"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("XB_USER_COUNTRY_ID must be 0..255")
		}
		s.kdc.UserCountryID = byte(n)
	}
	if v := get("XB_REPLAY_MAX"); v != "" {
		if s.kdc.ReplayMax, err = strconv.Atoi(v); err != nil || s.kdc.ReplayMax <= 0 {
			return nil, fmt.Errorf("XB_REPLAY_MAX must be a positive integer")
		}
	}
	for _, k := range []struct {
		env  string
		size int
		dst  **krb.Keyring
	}{
		{"XB_TGS_KEYRING_FILE", 16, &s.kdc.TGSKeys},
		{"XB_SG_KEYRING_FILE", 16, &s.kdc.SGKeys},
		{"XB_USER_KEY_SECRETS_FILE", 32, &s.kdc.UserKeys},
	} {
		path, err := req(k.env)
		if err != nil {
			return nil, err
		}
		if *k.dst, err = krb.LoadKeyring(path, k.size); err != nil {
			return nil, fmt.Errorf("%s: %w", k.env, err)
		}
	}
	for _, f := range []struct {
		env string
		dst *string
	}{
		{"XB_ACCOUNT_URL", &s.accountURL}, {"XB_ACCOUNT_CA_FILE", &s.accountCA},
		{"XB_TLS_CERT_FILE", &s.tlsCertFile}, {"XB_TLS_KEY_FILE", &s.tlsKeyFile},
	} {
		if *f.dst, err = req(f.env); err != nil {
			return nil, err
		}
	}
	return s, nil
}
