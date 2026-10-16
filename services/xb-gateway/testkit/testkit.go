// SPDX-License-Identifier: AGPL-3.0-only

// Package testkit exposes the xb-gateway UDP server to test/e2e, which sits
// outside this service's internal/ tree. Test support only; no command
// imports it.
package testkit

import (
	"io"
	"log/slog"
	"net/netip"

	"openpak/xb-live/internal/krb"
	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/services/xb-gateway/internal/gateway"
)

type Server = gateway.Server

// New builds a gateway on 127.0.0.1:0 advertising adv, validating tickets with
// the shared SG keyring and admitting users through xb-account, as cmd/xb-gateway does.
func New(adv netip.Addr, sgKeys *krb.Keyring, acct xbaccountapi.Resolver) (*Server, error) {
	cfg := gateway.DefaultConfig()
	cfg.BindAddr = netip.MustParseAddrPort("127.0.0.1:0")
	cfg.AdvertiseIP = adv
	cfg.InitRate, cfg.InitBurst = 1000, 1000
	s, err := gateway.NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)),
		gateway.KrbVerifier{SGKeys: sgKeys}, gateway.AccountDirectory{Resolver: acct}, nil)
	if err != nil {
		return nil, err
	}
	return s, s.Listen()
}
