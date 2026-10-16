// SPDX-License-Identifier: AGPL-3.0-only
package sgwire

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
)

// InitResponse describes the gateway's answer to a validated init packet.
type InitResponse struct {
	ClientSPI, GatewaySPI uint32 // u32 form (SPI in the upper three bytes)
	ClientNonce           [NonceLen]byte
	GatewayNonce          [NonceLen]byte
	XUID                  uint64
	ClientIP              [4]byte
	ClientPort            uint16
	TimeoutSecs           uint16
	PulseSecs             uint16
	GatewayDH             [DHLen]byte
	GatewayDES            [24]byte // sg-to-client 3DES key
}

var ErrAPRep = errors.New("cannot build AP-REP")

// BuildInitResponse marshals key-exchange, DH and AP-REP chunks. apRep receives
// the 20-byte HMAC-SHA1 (under the AP-REQ session key) over the first two chunks
// and returns the encoded AP-REP chunk body.
func BuildInitResponse(r InitResponse, sessionKey [16]byte, apRep func(subkey []byte) ([]byte, error)) ([]byte, error) {
	body := make([]byte, 0, 60)
	body = binary.LittleEndian.AppendUint16(body, 0) // version
	body = binary.LittleEndian.AppendUint16(body, 2) // 3DES
	body = binary.LittleEndian.AppendUint32(body, r.ClientSPI)
	body = binary.LittleEndian.AppendUint32(body, r.GatewaySPI)
	body = append(body, r.ClientNonce[:]...)
	body = append(body, r.GatewayNonce[:]...)
	body = append(body, 10, 0, 0, 100) // fixed in-tunnel client address
	body = binary.LittleEndian.AppendUint32(body, r.GatewaySPI)
	body = binary.LittleEndian.AppendUint64(body, r.XUID)
	body = append(body, 0, 0, 0, 0)
	body = append(body, r.ClientIP[:]...)
	body = binary.BigEndian.AppendUint16(body, r.ClientPort)
	body = binary.LittleEndian.AppendUint16(body, r.TimeoutSecs)
	body = binary.LittleEndian.AppendUint16(body, r.PulseSecs)
	body = append(body, 0, 0)
	chunk, err := MarshalChunks([]Chunk{{TagResponse, body}})
	if err != nil || len(chunk) != 0x40 {
		return nil, ErrAPRep
	}
	block, err := tdes(r.GatewayDES)
	if err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, r.GatewayNonce[:]).CryptBlocks(chunk[0x20:0x40], chunk[0x20:0x40])
	dh, err := MarshalChunks([]Chunk{{TagDH, r.GatewayDH[:]}})
	if err != nil {
		return nil, err
	}
	signed := append(chunk, dh...)
	mac := hmac.New(sha1.New, sessionKey[:])
	mac.Write(signed)
	rep, err := apRep(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	tail, err := MarshalChunks([]Chunk{{TagAPRep, rep}})
	if err != nil {
		return nil, err
	}
	return append(append([]byte{0, 0, 0, 0}, signed...), tail...), nil
}

// InitChecksum is the HMAC-SHA1 the client's authenticator must carry over the
// init and DH chunks (Init.SignedParameters).
func InitChecksum(sessionKey [16]byte, signedParameters []byte) []byte {
	mac := hmac.New(sha1.New, sessionKey[:])
	mac.Write(signedParameters)
	return mac.Sum(nil)
}

// Control payload builders for the encrypted data plane.
func PulseReply(seqAck uint32) ([]byte, error) {
	return MarshalChunks([]Chunk{{TagSgPulse, binary.LittleEndian.AppendUint32(nil, seqAck)}})
}
func DeleteNotice(reason uint32) ([]byte, error) {
	return MarshalChunks([]Chunk{{TagDelete, binary.LittleEndian.AppendUint32(nil, reason)}})
}

type QoS struct {
	Nonce  [8]byte
	Index  uint16
	Packet uint8
	Flags  uint8
}

func ParseQoS(data []byte) (QoS, error) {
	var q QoS
	if len(data) != 12 {
		return q, ErrMalformed
	}
	copy(q.Nonce[:], data)
	q.Index, q.Packet, q.Flags = binary.LittleEndian.Uint16(data[8:]), data[10], data[11]
	return q, nil
}
func QoSReply(q QoS, flags uint8, rtt, gap uint32) ([]byte, error) {
	b := append([]byte(nil), q.Nonce[:]...)
	b = binary.LittleEndian.AppendUint16(b, q.Index)
	b = append(b, q.Packet, flags)
	b = binary.LittleEndian.AppendUint32(b, rtt)
	b = binary.LittleEndian.AppendUint32(b, gap)
	return MarshalChunks([]Chunk{{TagQoSResp, b}})
}
