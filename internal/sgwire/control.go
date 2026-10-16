// SPDX-License-Identifier: AGPL-3.0-only
// Package sgwire ports Xombie's native security-gateway framing to Go.
package sgwire

import (
	"encoding/binary"
	"errors"
)

const (
	UDPPort     = 3074
	TagDelete   = 0x5300
	TagPulse    = 0x5301
	TagXbPulse  = 0x5302
	TagQoSInit  = 0x5307
	TagQoSResp  = 0x5308
	TagSgPulse  = 0x5309
	TagInit     = 0x5802
	TagResponse = 0x5803
	TagDH       = 0x5880
	TagAPReq    = 0x5882
	TagAPRep    = 0x5883
	TagPadding  = 0x5886
	MaxDatagram = 1500
)

var ErrMalformed = errors.New("malformed native gateway packet")

type Chunk struct {
	Tag  uint16
	Data []byte
}

func ParseChunks(data []byte) ([]Chunk, error) {
	if len(data) == 0 || len(data) > MaxDatagram {
		return nil, ErrMalformed
	}
	var chunks []Chunk
	for len(data) > 0 {
		if len(chunks) >= 32 || len(data) < 4 {
			return nil, ErrMalformed
		}
		tag := binary.LittleEndian.Uint16(data)
		length := int(binary.LittleEndian.Uint16(data[2:]))
		if length < 4 || length > len(data) {
			return nil, ErrMalformed
		}
		chunks = append(chunks, Chunk{tag, data[4:length]})
		data = data[length:]
	}
	return chunks, nil
}
func MarshalChunks(chunks []Chunk) ([]byte, error) {
	var output []byte
	for _, chunk := range chunks {
		if len(chunk.Data) > MaxDatagram-4 || len(output)+len(chunk.Data)+4 > MaxDatagram {
			return nil, ErrMalformed
		}
		header := [4]byte{}
		binary.LittleEndian.PutUint16(header[:], chunk.Tag)
		binary.LittleEndian.PutUint16(header[2:], uint16(len(chunk.Data)+4))
		output = append(output, header[:]...)
		output = append(output, chunk.Data...)
	}
	return output, nil
}

type Init struct {
	Version          uint16
	Flags            uint16
	SPI              uint32
	Nonce            [8]byte
	UserPermissions  uint32
	DHPublic         [96]byte
	APReq            []byte
	SignedParameters []byte
}

// ParseInit validates framing and returns borrowed slices. It does not establish
// authentication; the caller must verify AP-REQ, its checksum, freshness and replay.
func ParseInit(datagram []byte) (Init, error) {
	var result Init
	if len(datagram) < 4 || len(datagram) > MaxDatagram || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0 {
		return result, ErrMalformed
	}
	chunks, err := ParseChunks(datagram[4:])
	if err != nil {
		return result, err
	}
	if len(chunks) != 4 || chunks[0].Tag != TagInit || chunks[1].Tag != TagDH || chunks[2].Tag != TagAPReq || chunks[3].Tag != TagPadding {
		return result, ErrMalformed
	}
	if len(chunks[0].Data) != 20 || len(chunks[1].Data) != 96 || len(chunks[2].Data) == 0 {
		return result, ErrMalformed
	}
	data := chunks[0].Data
	result.Version = binary.LittleEndian.Uint16(data)
	result.Flags = binary.LittleEndian.Uint16(data[2:])
	result.SPI = binary.LittleEndian.Uint32(data[4:])
	copy(result.Nonce[:], data[8:16])
	result.UserPermissions = binary.LittleEndian.Uint32(data[16:])
	copy(result.DHPublic[:], chunks[1].Data)
	// The init chunk carries the 24-bit SPI in the upper three bytes of a u32.
	if result.SPI == 0 || result.SPI&0xff != 0 {
		return Init{}, ErrMalformed
	}
	result.APReq = chunks[2].Data
	// The native checksum covers the init and DH chunks, including their headers.
	result.SignedParameters = datagram[4:128]
	return result, nil
}
