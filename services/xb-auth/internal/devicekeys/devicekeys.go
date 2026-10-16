// SPDX-License-Identifier: AGPL-3.0-only
// Package devicekeys is a file-backed kdc.DeviceKeys: a secret JSON file
// {"<machine id>":"<32 hex machine key>"}. It is an interim store until
// xb-account owns device proof material. An absent file means no device has
// proof material, so MACS answers "principal unknown" for everyone.
package devicekeys

import (
	"context"
	"encoding/hex"
	"encoding/json"
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
