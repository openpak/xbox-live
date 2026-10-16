// SPDX-License-Identifier: AGPL-3.0-only
// Package devicekeys adapts device proof material to kdc.DeviceKeys.
// Remote (production) asks xb-account over mTLS, which owns the keys and
// releases one only for a device that is currently admitted. Store is a
// TEST-ONLY file-backed variant: a secret JSON file {"<machine id>":"<32 hex
// machine key>"}; cmd/xb-auth does not use it.
package devicekeys

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"openpak/xb-live/internal/xbaccountapi"
	"openpak/xb-live/internal/xbcrypto"
	"openpak/xb-live/services/xb-auth/internal/kdc"
)

type Store map[string]xbcrypto.Key

// None is the store used when no file is configured.
var None = Store{}

func Load(path string) (Store, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s is writable by group or others", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("device keys: %w", err)
	}
	s := Store{}
	for id, h := range raw {
		b, err := hex.DecodeString(h)
		if !xbaccountapi.ValidID(id) || err != nil || len(b) != 16 {
			return nil, fmt.Errorf("device keys: invalid entry %q", id)
		}
		var k xbcrypto.Key
		copy(k[:], b)
		s[id] = k
		if k == (xbcrypto.Key{}) {
			return nil, fmt.Errorf("device keys: all-zero key for %q", id)
		}
	}
	return s, nil
}

func (s Store) MachineKey(_ context.Context, id string) (xbcrypto.Key, error) {
	if k, ok := s[id]; ok {
		return k, nil
	}
	return xbcrypto.Key{}, kdc.ErrNoDeviceKey
}

// Remote is the production kdc.DeviceKeys: it maps xb-account's answers onto
// the KDC's: not found, denied and invalid all mean "no proof material"
// (MACS: principal unknown); any other failure is a service error.
type Remote struct{ Keys xbaccountapi.DeviceKeys }

func (r Remote) MachineKey(ctx context.Context, id string) (xbcrypto.Key, error) {
	k, err := r.Keys.DeviceKey(ctx, id)
	switch {
	case err == nil:
		return k, nil
	case errors.Is(err, xbaccountapi.ErrNotFound), errors.Is(err, xbaccountapi.ErrDenied), errors.Is(err, xbaccountapi.ErrInvalid):
		return xbcrypto.Key{}, kdc.ErrNoDeviceKey
	}
	return xbcrypto.Key{}, err
}
