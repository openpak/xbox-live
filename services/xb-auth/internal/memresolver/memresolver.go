// SPDX-License-Identifier: AGPL-3.0-only
// Package memresolver is a TEST-ONLY in-memory xbaccountapi.Resolver and
// kdc.DeviceKeys. cmd/xb-auth does not import it and offers no way to enable
// it in a deployment.
package memresolver

import (
	"context"
	"strings"
	"sync"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcrypto"
	"openpak/xb-live/services/xb-auth/internal/kdc"
)

type Resolver struct {
	mu          sync.Mutex
	users       map[string]xbaccountapi.Principal // lower-case gamertag
	byID        map[string]xbaccountapi.Principal // kind+id
	keys        map[string]xbcrypto.Key
	Unavailable bool
}

func New() *Resolver {
	return &Resolver{users: map[string]xbaccountapi.Principal{}, byID: map[string]xbaccountapi.Principal{}, keys: map[string]xbcrypto.Key{}}
}

// SetUser registers a user (id = XUID hex) with the given status.
func (r *Resolver) SetUser(gamertag, xuid string, st xbaccountapi.Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := xbaccountapi.Principal{Kind: xbaccountapi.KindUser, PrincipalID: xuid, CoreAccountID: "acct-" + xuid, Status: st, Gamertag: gamertag}
	r.users[strings.ToLower(gamertag)] = p
	r.byID["user/"+xuid] = p
}

// Remove forgets a user entirely (unknown to the account service).
func (r *Resolver) Remove(gamertag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	g := strings.ToLower(gamertag)
	if p, ok := r.users[g]; ok {
		delete(r.byID, "user/"+p.PrincipalID)
	}
	delete(r.users, g)
}

// SetDevice registers a device (id = machine id hex) and, if key is non-nil, its machine key.
func (r *Resolver) SetDevice(machineID string, st xbaccountapi.Status, key *xbcrypto.Key) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID["device/"+machineID] = xbaccountapi.Principal{Kind: xbaccountapi.KindDevice, PrincipalID: machineID,
		CoreAccountID: "acct-" + machineID, Status: st}
	if key != nil {
		r.keys[machineID] = *key
	}
}

func answer(p xbaccountapi.Principal, ok bool) (xbaccountapi.Principal, error) {
	switch {
	case !ok:
		return xbaccountapi.Principal{}, xbaccountapi.ErrNotFound
	case p.Status != xbaccountapi.StatusActive:
		return xbaccountapi.Principal{}, &xbaccountapi.DeniedError{Principal: p}
	}
	return p, nil
}

func (r *Resolver) lookup(key string) (xbaccountapi.Principal, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Unavailable {
		return xbaccountapi.Principal{}, xbaccountapi.ErrUnavailable
	}
	p, ok := r.byID[key]
	return answer(p, ok)
}

func (r *Resolver) ResolveUser(_ context.Context, xuid string) (xbaccountapi.Principal, error) {
	return r.lookup("user/" + xuid)
}

func (r *Resolver) ResolveDevice(_ context.Context, id string) (xbaccountapi.Principal, error) {
	return r.lookup("device/" + id)
}

func (r *Resolver) ResolveGamertag(_ context.Context, tag string) (xbaccountapi.Principal, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Unavailable {
		return xbaccountapi.Principal{}, xbaccountapi.ErrUnavailable
	}
	p, ok := r.users[strings.ToLower(tag)]
	return answer(p, ok)
}

// MachineKey implements kdc.DeviceKeys.
func (r *Resolver) MachineKey(_ context.Context, id string) (xbcrypto.Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys[id]; ok {
		return k, nil
	}
	return xbcrypto.Key{}, kdc.ErrNoDeviceKey
}
