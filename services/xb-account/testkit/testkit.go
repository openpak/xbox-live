// SPDX-License-Identifier: AGPL-3.0-only

// Package testkit exposes an in-process xb-account (real store, provisioner,
// resolver and HTTP routes over a fake account core) to test/e2e, which sits
// outside this service's internal/ tree. It is test support only: no command
// imports it and it offers nothing a deployment can enable.
package testkit

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"openpak/xb-live/services/xb-account/internal/api"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
	"openpak/xb-live/services/xb-account/internal/coretest"
	"openpak/xb-live/services/xb-account/internal/enrol"
	"openpak/xb-live/services/xb-account/internal/provision"
	"openpak/xb-live/services/xb-account/internal/resolver"
	"openpak/xb-live/services/xb-account/internal/revoke"
	"openpak/xb-live/services/xb-account/internal/store"
	"openpak/xb-live/services/xb-account/internal/voucher"
)

// SPIFFE identities the routes authorize.
const (
	Auth        = api.Auth
	Gateway     = api.Gateway
	Provisioner = api.Provisioner
	Enroll      = api.Enroll
)

// Account is a running xb-account stack. Handler must be served over mutual
// TLS: every route checks the peer's SPIFFE URI.
type Account struct {
	Handler http.Handler
	Core    *coretest.Core
	db      *store.Store
	proc    *revoke.Processor
	// Enrol and Vouchers are the in-process services behind the enrolment
	// routes, for tests that play the dashboard (CompleteSignup, Check).
	Enrol    *enrol.Service
	Vouchers *voucher.Service

	mu     sync.Mutex
	offset time.Duration
}

// Advance moves the stack's clock forward (enrolment/voucher expiry tests).
func (a *Account) Advance(d time.Duration) {
	a.mu.Lock()
	a.offset += d
	a.mu.Unlock()
}

func (a *Account) now() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Now().Add(a.offset)
}

// New opens a store under dir. Close it when done.
func New(dir string) (*Account, error) {
	db, err := store.Open(filepath.Join(dir, "xb-account.db"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		return nil, err
	}
	c := coretest.New()
	res := &resolver.Resolver{Core: c, Store: db}
	prov := &provision.Provisioner{Core: c, Store: db}
	a := &Account{Core: c, db: db, proc: &revoke.Processor{Core: c, Store: db}}
	db.SetClock(a.now)
	a.Vouchers = &voucher.Service{Core: c, Store: db, Now: a.now}
	a.Enrol = &enrol.Service{Core: c, Store: db, Vouchers: a.Vouchers, Now: a.now}
	a.Handler = api.HandlerFull(res, res, res, prov, a.Enrol, a.Vouchers)
	return a, nil
}

func (a *Account) Close() error { return a.db.Close() }

// AddActiveAccount creates an active core account (the web user).
func (a *Account) AddActiveAccount(id string) {
	a.Core.AddAccount(id, pb.AccountStatus_ACCOUNT_STATUS_ACTIVE)
}

// EmitAndProcess delivers a core event and applies it, like the event loop.
func (a *Account) EmitAndProcess(ctx context.Context, typ, account, namespace, subject string) error {
	a.Core.Emit(typ, account, namespace, subject)
	_, err := a.proc.ProcessOnce(ctx)
	return err
}

// RevokeLinkInCore flips the user's core link to revoked WITHOUT delivering
// an event, simulating an unlink xb-account has not heard about yet.
func (a *Account) RevokeLinkInCore(ctx context.Context, xuid string) error {
	l, err := a.Core.GetLinkBySubject(ctx, xuid)
	if err != nil {
		return err
	}
	a.Core.SetLinkState(l.LinkID, pb.LinkState_LINK_STATE_REVOKED)
	return nil
}

// DeviceXUID returns the XUID reserved for an enrolled device.
func (a *Account) DeviceXUID(t interface{ Fatalf(string, ...any) }, machineID string) string {
	d, err := a.db.GetDevice(context.Background(), machineID)
	if err != nil || d.XUID == "" {
		t.Fatalf("no device XUID: %v", err)
	}
	return d.XUID
}
