// SPDX-License-Identifier: AGPL-3.0-only
package krb

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"openpak/xb-live/internal/xbcrypto"
)

// UsageMachineAccount is the key usage Xombie uses to seal the account blob in
// PA_XBOX_ACCOUNT_CREATION.
const UsageMachineAccount = 1203

// MachineIDFromSerial maps a 12-digit console serial number to the 16-hex
// machine id used with xbaccountapi.Resolver.ResolveDevice and returns its
// numeric form. The serial must be exactly 12 ASCII digits and non-zero.
func MachineIDFromSerial(serial string) (string, uint64, error) {
	if len(serial) != 12 {
		return "", 0, errors.New("krb: serial must be 12 digits")
	}
	var n uint64
	for _, c := range []byte(serial) {
		if c < '0' || c > '9' {
			return "", 0, errors.New("krb: serial must be 12 digits")
		}
		n = n*10 + uint64(c-'0')
	}
	if n == 0 {
		return "", 0, errors.New("krb: zero serial")
	}
	return fmt.Sprintf("%016x", n), n, nil
}

// VerifyClientVersion checks PA_XBOX_CLIENT_VERSION in a machine (MACS)
// request: SHA-1 HMAC, keyed by the nonce-0 key of the machine key, prefixed
// to the version string. It returns the version text.
func VerifyClientVersion(machine xbcrypto.Key, payload []byte) ([]byte, bool) {
	if len(payload) <= sha1.Size {
		return nil, false
	}
	k := xbcrypto.NonceKey(machine, 0)
	mac := hmac.New(sha1.New, k[:])
	mac.Write(payload[sha1.Size:])
	if subtle.ConstantTimeCompare(mac.Sum(nil), payload[:sha1.Size]) != 1 {
		return nil, false
	}
	return payload[sha1.Size:], true
}

// SignClientVersion builds a PA_XBOX_CLIENT_VERSION value (used by tests and
// in-process clients).
func SignClientVersion(machine xbcrypto.Key, version []byte) []byte {
	k := xbcrypto.NonceKey(machine, 0)
	mac := hmac.New(sha1.New, k[:])
	mac.Write(version)
	return append(mac.Sum(nil), version...)
}

const (
	gamertagField = 16
	domainField   = 20
	realmField    = 24
)

// MachineAccount is the account blob handed to a console in
// PA_XBOX_ACCOUNT_CREATION: xuid(LE) gamertag[16] domain[20] realm[24] key[16].
type MachineAccount struct {
	XUID     uint64
	Gamertag string
	Domain   string
	Realm    string
	Key      xbcrypto.Key
}

func (a MachineAccount) Marshal() ([]byte, error) {
	if len(a.Gamertag) >= gamertagField || len(a.Domain) >= domainField || len(a.Realm) >= realmField {
		return nil, errors.New("krb: account field too long")
	}
	b := make([]byte, 8+gamertagField+domainField+realmField+16)
	binary.LittleEndian.PutUint64(b, a.XUID)
	copy(b[8:], a.Gamertag)
	copy(b[8+gamertagField:], a.Domain)
	copy(b[8+gamertagField+domainField:], a.Realm)
	copy(b[8+gamertagField+domainField+realmField:], a.Key[:])
	return b, nil
}

// DeriveDeviceKey derives the account key of a console's machine account
// (gamertag SN.<serial>), separate from user keys.
func DeriveDeviceKey(secret []byte, machineID uint64) xbcrypto.Key {
	return deriveKey(secret, "openpak-xb-device-key-v1", machineID)
}
