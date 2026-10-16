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

	"openpak/xb-live/services/xb-account/internal/api"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
	"openpak/xb-live/services/xb-account/internal/coretest"
	"openpak/xb-live/services/xb-account/internal/provision"
	"openpak/xb-live/services/xb-account/internal/resolver"
	"openpak/xb-live/services/xb-account/internal/revoke"
	"openpak/xb-live/services/xb-account/internal/store"
)

// SPIFFE identities the routes authorize.
const (
	Auth        = api.Auth
	Gateway     = api.Gateway
	Provisioner = api.Provisioner
)

// Account is a running xb-account stack. Handler must be served over mutual
// TLS: every route checks the peer's SPIFFE URI.
type Account struct {
	Handler http.Handler
	Core    *coretest.Core
	db      *store.Store
	proc    *revoke.Processor
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
	return &Account{Handler: api.Handler(res, res, res, prov), Core: c, db: db, proc: &revoke.Processor{Core: c, Store: db}}, nil
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
