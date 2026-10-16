// SPDX-License-Identifier: AGPL-3.0-only
package krb

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"

	"openpak/xb-live/internal/xbcrypto"
)

// Keyring holds rotation-identified secrets. Ids are the Kerberos key version
// numbers carried in encrypted tickets, so a verifier picks the right key and
// old tickets keep working until their keys are removed.
type Keyring struct {
	active uint32
	keys   map[uint32][]byte
}

// Public Xombie prototype keys. They appear in the open-source tree and must
// never protect a deployment.
var knownPublicKeys = [][]byte{
	mustHex("205cbb97cff0058123c22658fecd6898"), // Xombie SG master key
	mustHex("b274d292fe16a0175870db617b02d0ad"), // Xombie devkit machine key
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

type keyringFile struct {
	Active uint32            `json:"active"`
	Keys   map[string]string `json:"keys"`
}

// ParseKeyring parses {"active":2,"keys":{"1":"<hex>","2":"<hex>"}}.
// Every key must be exactly size bytes, non-zero, not a known public key and
// unique within the ring. The active id must exist.
func ParseKeyring(data []byte, size int) (*Keyring, error) {
	var f keyringFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	if len(f.Keys) == 0 || len(f.Keys) > 8 {
		return nil, errors.New("keyring: need 1 to 8 keys")
	}
	k := &Keyring{active: f.Active, keys: map[uint32][]byte{}}
	seen := map[string]bool{}
	for ids, h := range f.Keys {
		id, err := strconv.ParseUint(ids, 10, 32)
		if err != nil || id == 0 {
			return nil, errors.New("keyring: key ids must be positive 32-bit integers")
		}
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != size {
			return nil, fmt.Errorf("keyring: key %s must be %d hexadecimal bytes", ids, size)
		}
		if bytes.Equal(raw, make([]byte, size)) {
			return nil, fmt.Errorf("keyring: key %s is all zero", ids)
		}
		for _, pub := range knownPublicKeys {
			if bytes.Equal(raw, pub) {
				return nil, fmt.Errorf("keyring: key %s is a published prototype key", ids)
			}
		}
		if seen[h] {
			return nil, errors.New("keyring: duplicate key material")
		}
		seen[h] = true
		k.keys[uint32(id)] = raw
	}
	if _, ok := k.keys[k.active]; !ok {
		return nil, errors.New("keyring: active id has no key")
	}
	return k, nil
}

// LoadKeyring reads a keyring secret file. Group/world-writable files are refused.
func LoadKeyring(path string, size int) (*Keyring, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("keyring %s is writable by group or others", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKeyring(data, size)
}

func (k *Keyring) Active() (uint32, []byte) { return k.active, k.keys[k.active] }

func (k *Keyring) Get(id uint32) ([]byte, bool) { v, ok := k.keys[id]; return v, ok }

// IDs returns every id, the active one first, the rest ascending.
func (k *Keyring) IDs() []uint32 {
	ids := make([]uint32, 0, len(k.keys))
	for id := range k.keys {
		if id != k.active {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return append([]uint32{k.active}, ids...)
}

// Shares reports whether two rings contain any identical key material.
func (k *Keyring) Shares(o *Keyring) bool {
	for _, a := range k.keys {
		for _, b := range o.keys {
			if bytes.Equal(a, b) {
				return true
			}
		}
	}
	return false
}

// DeriveUserKey derives the 16-byte account key of the console user with the
// given XUID from a secret ring entry. Account core never stores it; xb-auth
// can recompute it (and a provisioning path can hand it to the console).
func DeriveUserKey(secret []byte, xuid uint64) xbcrypto.Key {
	return deriveKey(secret, "openpak-xb-user-key-v1", xuid)
}

func deriveKey(secret []byte, label string, id uint64) xbcrypto.Key {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], id)
	mac.Write(x[:])
	var key xbcrypto.Key
	copy(key[:], mac.Sum(nil))
	return key
}

// NewSessionKey returns a fresh random session key.
func NewSessionKey() (xbcrypto.Key, error) {
	var k xbcrypto.Key
	_, err := rand.Read(k[:])
	return k, err
}

// ErrDecrypt is returned when a ciphertext fails authentication or has an
// unsupported encryption type or key version.
var ErrDecrypt = errors.New("krb: cannot decrypt")

// Seal encrypts plaintext under key with RC4-HMAC using a fresh random confounder.
func Seal(key xbcrypto.Key, usage uint32, kvno *uint32, plaintext []byte) (EncryptedData, error) {
	c, err := xbcrypto.Seal(key, usage, plaintext)
	if err != nil {
		return EncryptedData{}, err
	}
	return EncryptedData{EType: ETypeRC4HMAC, KVNO: kvno, Cipher: c}, nil
}

// Open authenticates and decrypts e.
func Open(key xbcrypto.Key, usage uint32, e EncryptedData) ([]byte, error) {
	if e.EType != ETypeRC4HMAC {
		return nil, ErrDecrypt
	}
	p, err := xbcrypto.Open(key, usage, e.Cipher)
	if err != nil {
		return nil, ErrDecrypt
	}
	return p, nil
}

// ToKey converts a 16-byte slice to a Key.
func ToKey(b []byte) (xbcrypto.Key, error) {
	var k xbcrypto.Key
	if len(b) != len(k) {
		return k, ErrDecrypt
	}
	copy(k[:], b)
	return k, nil
}

// OpenTicket decrypts the encrypted part of a ticket using the ring entry named
// by its key version number. A missing or unknown key version is refused. The
// security gateway uses it with UsageSGTicket and the shared service ring.
func OpenTicket(ring *Keyring, usage uint32, t Ticket) (*EncTicketPart, error) {
	if t.Enc.KVNO == nil {
		return nil, ErrDecrypt
	}
	raw, ok := ring.Get(*t.Enc.KVNO)
	if !ok {
		return nil, ErrDecrypt
	}
	key, err := ToKey(raw)
	if err != nil {
		return nil, err
	}
	plain, err := Open(key, usage, t.Enc)
	if err != nil {
		return nil, err
	}
	return ParseEncTicketPart(plain)
}
