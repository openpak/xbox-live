// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"testing"

	"openpak/xb-live/internal/xbaccountapi"
)

type kindResolver struct{ user, device int }

func (r *kindResolver) ResolveUser(_ context.Context, id string) (xbaccountapi.Principal, error) {
	r.user++
	return xbaccountapi.Principal{Kind: xbaccountapi.KindUser, PrincipalID: id, Status: xbaccountapi.StatusActive}, nil
}
func (r *kindResolver) ResolveDevice(_ context.Context, id string) (xbaccountapi.Principal, error) {
	r.device++
	return xbaccountapi.Principal{Kind: xbaccountapi.KindDevice, PrincipalID: id, Status: xbaccountapi.StatusActive}, nil
}
func (r *kindResolver) ResolveGamertag(context.Context, string) (xbaccountapi.Principal, error) {
	panic("unused")
}

// A machine-account ticket (console before any user signs in) resolves through
// the device path; user XUIDs never do.
func TestAccountDirectoryRoutesMachineIDs(t *testing.T) {
	r := &kindResolver{}
	d := AccountDirectory{Resolver: r}
	if p, err := d.ResolveUser(context.Background(), 884985900905); err != nil || !p.Active || r.device != 1 || r.user != 0 {
		t.Fatalf("machine id: %+v %v %+v", p, err, r)
	}
	if p, err := d.ResolveUser(context.Background(), 0x0009000000000001); err != nil || !p.Active || r.user != 1 {
		t.Fatalf("user xuid: %+v %v %+v", p, err, r)
	}
}
