// SPDX-License-Identifier: AGPL-3.0-only
// Package xbcrypto implements the legacy native Xbox algorithms ported from
// Xombie's libs/xblive/src/crypto. These algorithms serve protocol compatibility.
package xbcrypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"errors"
)

type Key [16]byte

var ErrAuthentication = errors.New("native authentication failed")

func md5HMAC(key []byte, parts ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}
func sha1HMAC(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha1.New, key)
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}
func nonceBytes(nonce uint32) []byte {
	var value [4]byte
	binary.LittleEndian.PutUint32(value[:], nonce)
	return value[:]
}

// Seal uses a new operating-system random confounder for every native message.
func Seal(key Key, usage uint32, plaintext []byte) ([]byte, error) {
	var confounder [8]byte
	if _, err := rand.Read(confounder[:]); err != nil {
		return nil, err
	}
	return seal(key, usage, plaintext, confounder)
}
func seal(key Key, usage uint32, plaintext []byte, confounder [8]byte) ([]byte, error) {
	stateKey := md5HMAC(key[:], nonceBytes(usage))
	message := make([]byte, 8+len(plaintext))
	copy(message, confounder[:])
	copy(message[8:], plaintext)
	checksum := md5HMAC(stateKey, message)
	cipherKey := md5HMAC(stateKey, checksum)
	cipher, err := rc4.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	output := make([]byte, 16+len(message))
	copy(output, checksum)
	cipher.XORKeyStream(output[16:], message)
	return output, nil
}
func Open(key Key, usage uint32, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 {
		return nil, ErrAuthentication
	}
	checksum := ciphertext[:16]
	stateKey := md5HMAC(key[:], nonceBytes(usage))
	cipherKey := md5HMAC(stateKey, checksum)
	cipher, err := rc4.NewCipher(cipherKey)
	if err != nil {
		return nil, ErrAuthentication
	}
	plaintext := make([]byte, len(ciphertext)-16)
	cipher.XORKeyStream(plaintext, ciphertext[16:])
	if !hmac.Equal(checksum, md5HMAC(stateKey, plaintext)) {
		clear(plaintext)
		return nil, ErrAuthentication
	}
	return plaintext[8:], nil
}

func permute(first Key, second []byte, salt uint32) Key {
	derived := md5HMAC(first[:], []byte("signaturekey\x00"))
	digest := md5.New()
	digest.Write(nonceBytes(salt))
	digest.Write(second)
	var result Key
	copy(result[:], md5HMAC(derived, digest.Sum(nil)))
	return result
}
func NonceKey(session Key, nonce uint32) Key { return permute(session, nonceBytes(nonce), 1026) }
func CompoundKey(client, session Key) Key    { return permute(client, session[:], 1024) }

func MachineKey(hdd, online Key) Key {
	morph := []byte{0x60, 0x59, 0xe8, 0x2e, 0xdf, 0xbf, 0x7f, 0xd3, 0x23, 0x35, 0x74, 0x2a, 0x64, 0x8b, 0xb1, 0x2c}
	cipherKey := sha1HMAC(morph, hdd[:])
	cipher, _ := rc4.NewCipher(cipherKey)
	var result Key
	cipher.XORKeyStream(result[:], online[:])
	return result
}
