// SPDX-License-Identifier: AGPL-3.0-only
// Derived from Xombie's libs/xblive/src/crypto (derivation.rs, primitives.rs).
package sgwire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

const (
	DHLen    = 96 // 768-bit First Oakley Group
	NonceLen = 8
)

var ErrDH = errors.New("invalid Diffie-Hellman value")

var oakleyPrime = new(big.Int).SetBytes([]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
	0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
	0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
	0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
	0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
})

func leToBig(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}
func bigToLE(n *big.Int, size int) [DHLen]byte {
	var out [DHLen]byte
	be := n.Bytes()
	for i := range be {
		out[len(be)-1-i] = be[i]
	}
	return out
}

// DHPrivate is a per-connection secret exponent.
type DHPrivate struct{ x *big.Int }

// GenerateDH draws a 256-bit exponent from r (crypto/rand when nil) and returns
// the little-endian public value g^x, as the native protocol expects.
func GenerateDH(r io.Reader) (*DHPrivate, [DHLen]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	var raw [32]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return nil, [DHLen]byte{}, err
	}
	raw[31] |= 0x80
	x := leToBig(raw[:])
	pub := new(big.Int).Exp(big.NewInt(2), x, oakleyPrime)
	return &DHPrivate{x}, bigToLE(pub, DHLen), nil
}

// Secret validates the peer value (2 <= y <= p-2) and returns y^x mod p, little endian.
func (p *DHPrivate) Secret(peer []byte) ([DHLen]byte, error) {
	if len(peer) != DHLen {
		return [DHLen]byte{}, ErrDH
	}
	y := leToBig(peer)
	max := new(big.Int).Sub(oakleyPrime, big.NewInt(2))
	if y.Cmp(big.NewInt(2)) < 0 || y.Cmp(max) > 0 {
		return [DHLen]byte{}, ErrDH
	}
	return bigToLE(new(big.Int).Exp(y, p.x, oakleyPrime), DHLen), nil
}

// OneWayKeys protect one direction of a connection.
type OneWayKeys struct {
	SHA [16]byte
	DES [24]byte
	IV  [8]byte
}
type ConnectionKeys struct{ ClientToSG, SGToClient OneWayKeys }

// DeriveKeys expands the AP-REQ session key, DH secret and both nonces into the
// per-direction key sets (five HMAC-SHA1 blocks, native layout).
func DeriveKeys(sessionKey [16]byte, dh [DHLen]byte, clientNonce, gatewayNonce [NonceLen]byte) ConnectionKeys {
	var stream []byte
	low := binary.LittleEndian.Uint32(dh[:4])
	for i := uint32(0); i < 5; i++ {
		var word [4]byte
		binary.LittleEndian.PutUint32(word[:], low+i)
		h := hmac.New(sha1.New, sessionKey[:])
		h.Write(word[:])
		h.Write(dh[4:])
		h.Write(clientNonce[:])
		h.Write(gatewayNonce[:])
		stream = h.Sum(stream)
	}
	var k ConnectionKeys
	copy(k.ClientToSG.SHA[:], stream[0:16])
	copy(k.ClientToSG.DES[:], stream[16:40])
	copy(k.SGToClient.SHA[:], stream[40:56])
	copy(k.SGToClient.DES[:], stream[56:80])
	copy(k.ClientToSG.IV[:], stream[80:88])
	copy(k.SGToClient.IV[:], stream[88:96])
	return k
}

// PermuteIV mixes the packet sequence number into the direction IV.
func PermuteIV(iv [8]byte, seq uint32) [8]byte {
	v := binary.LittleEndian.Uint64(iv[:])
	lo, hi := v&0xffffffff, v>>32
	fullLo, fullHi := lo*uint64(seq), hi*uint64(seq)
	outLo := (fullLo ^ (fullHi >> 32)) & 0xffffffff
	outHi := (fullHi ^ (fullLo >> 32)) & 0xffffffff
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], outLo|outHi<<32)
	return out
}
