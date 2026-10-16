// SPDX-License-Identifier: AGPL-3.0-only
// Derived from Xombie's libs/xblive/src/sg/{packet,seq,tcp}.rs.
package sgwire

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
)

type Opcode uint8

const (
	OpControl Opcode = iota
	OpTCP0
	OpTCP1
	OpTCP2
)

const (
	headerLen = 4
	seqLen    = 2
	digestLen = 10
	blockSize = 8
	MinPacket = headerLen + seqLen + digestLen
)

var (
	ErrPacket = errors.New("invalid native gateway packet")
	ErrAuth   = errors.New("native packet authentication failed")
	ErrReplay = errors.New("native packet replayed or too old")
)

func (o Opcode) FooterLen() int {
	switch o {
	case OpTCP0:
		return 12
	case OpTCP1:
		return 14
	case OpTCP2:
		return 16
	}
	return 0
}

// SPI is the 3-byte security parameters index carried in every packet header.
type SPI [3]byte

// SPIFromInit converts the init chunk's u32 form (value in the upper three bytes).
func SPIFromU32(v uint32) SPI { return SPI{byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
func (s SPI) U32() uint32     { return uint32(s[0])<<8 | uint32(s[1])<<16 | uint32(s[2])<<24 }

// Packet is an authenticated, decrypted data-plane packet. Payload and Footer
// are owned by the caller.
type Packet struct {
	Opcode  Opcode
	SPI     SPI
	Seq     uint32
	Payload []byte
	Footer  []byte
}

// PeekSPI classifies a datagram: init (prefix 0, SPI 0), session (non-zero SPI) or invalid.
func PeekSPI(datagram []byte) (spi SPI, isInit bool, ok bool) {
	if len(datagram) < headerLen {
		return SPI{}, false, false
	}
	spi = SPI{datagram[1], datagram[2], datagram[3]}
	if spi == (SPI{}) {
		return spi, datagram[0] == 0, datagram[0] == 0
	}
	return spi, false, true
}

func tdes(key [24]byte) (cipher.Block, error) { return des.NewTripleDESCipher(key[:]) }

func digest(key [16]byte, footer, hiddenSeq, header, payload []byte, padding int) []byte {
	h := hmac.New(sha1.New, key[:])
	h.Write(footer)
	h.Write(hiddenSeq)
	h.Write(header)
	h.Write(make([]byte, padding))
	h.Write(payload)
	return h.Sum(nil)[:digestLen]
}
func digestPadding(footerLen int) int { return (4 - ((footerLen + 2) % 4)) % 4 }

// Seal encrypts and signs a packet. seq must be non-zero; footer must be the
// exact protocol footer for the opcode.
func Seal(keys OneWayKeys, op Opcode, spi SPI, seq uint32, payload, footer []byte) ([]byte, error) {
	if seq == 0 || len(footer) != op.FooterLen() || len(payload) > MaxDatagram {
		return nil, ErrPacket
	}
	pad := (blockSize - len(payload)%blockSize) % blockSize
	buf := []byte{byte(pad<<5) | byte(op), spi[0], spi[1], spi[2]}
	buf = append(buf, payload...)
	if len(footer) < pad {
		buf = append(buf, make([]byte, pad-len(footer))...)
	}
	buf = append(buf, footer...)
	buf = append(buf, byte(seq), byte(seq>>8))
	encEnd := headerLen + len(payload) + pad
	if encEnd > len(buf)-seqLen {
		return nil, ErrPacket
	}
	block, err := tdes(keys.DES)
	if err != nil {
		return nil, err
	}
	iv := PermuteIV(keys.IV, seq)
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(buf[headerLen:encEnd], buf[headerLen:encEnd])
	hidden := []byte{byte(seq >> 16), byte(seq >> 24)}
	buf = append(buf, digest(keys.SHA, buf[encEnd:], hidden, buf[:headerLen], buf[headerLen:encEnd], digestPadding(len(buf)-encEnd))...)
	if len(buf) > MaxDatagram {
		return nil, ErrPacket
	}
	return buf, nil
}

// Open authenticates and decrypts a datagram. highest is the largest sequence
// number accepted so far; it selects the 16-bit rollover candidate. Replay
// rejection is a separate step (ReplayWindow) performed only after Open succeeds.
func Open(buf []byte, keys OneWayKeys, highest uint32) (Packet, error) {
	var p Packet
	if len(buf) < MinPacket || len(buf) > MaxDatagram {
		return p, ErrPacket
	}
	if buf[0]&0x0f > byte(OpTCP2) {
		return p, ErrPacket
	}
	op := Opcode(buf[0] & 0x0f)
	pad := int(buf[0] >> 5)
	pfl := op.FooterLen()
	unenc := 0
	if pfl >= pad {
		unenc = pfl - pad
	}
	encLen := len(buf) - MinPacket - unenc
	if encLen < pad || encLen%blockSize != 0 {
		return p, ErrPacket
	}
	encEnd := headerLen + encLen
	footerEnd := encEnd + unenc + seqLen
	footerSeg := buf[encEnd:footerEnd]
	padding := digestPadding(unenc + seqLen)
	var seq uint32
	found := false
	for _, add := range [...]uint16{0, 1, 0xffff} {
		hi := uint16(highest>>16) + add
		hidden := []byte{byte(hi), byte(hi >> 8)}
		want := digest(keys.SHA, footerSeg, hidden, buf[:headerLen], buf[headerLen:encEnd], padding)
		if hmac.Equal(want, buf[footerEnd:footerEnd+digestLen]) {
			seq = uint32(hi)<<16 | uint32(footerSeg[unenc]) | uint32(footerSeg[unenc+1])<<8
			found = true
			break
		}
	}
	if !found || seq == 0 {
		return p, ErrAuth
	}
	block, err := tdes(keys.DES)
	if err != nil {
		return p, err
	}
	data := append([]byte(nil), buf[headerLen:footerEnd]...)
	iv := PermuteIV(keys.IV, seq)
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(data[:encLen], data[:encLen])
	payloadLen := encLen - pad
	p = Packet{Opcode: op, SPI: SPI{buf[1], buf[2], buf[3]}, Seq: seq, Payload: data[:payloadLen]}
	base := len(data) - pfl - seqLen
	if base < 0 {
		return Packet{}, ErrPacket
	}
	p.Footer = data[base : base+pfl]
	return p, nil
}

// ReplayWindow is a 64-packet sliding anti-replay window over authenticated sequence numbers.
type ReplayWindow struct {
	Highest uint32
	bitmap  uint64
}

// Accept records seq and reports false for duplicates and packets older than the window.
func (w *ReplayWindow) Accept(seq uint32) bool {
	switch {
	case seq > w.Highest:
		shift := seq - w.Highest
		if shift >= 64 {
			w.bitmap = 1
		} else {
			w.bitmap = w.bitmap<<shift | 1
		}
		w.Highest = seq
		return true
	default:
		diff := w.Highest - seq
		if diff >= 64 || w.bitmap&(1<<diff) != 0 {
			return false
		}
		w.bitmap |= 1 << diff
		return true
	}
}

// TCP flags and header for the SG-tunnelled TCP segments.
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10

	tcpBasePort = 1000
)

type TCPHeader struct {
	Src, Dst       uint16
	Seq, Ack       uint32
	FlagsAndHeader uint16
	Window         uint16
}

func (h TCPHeader) Flags() uint16 { return h.FlagsAndHeader & 0x0fff }

// OptionsLen returns the byte length of TCP options that prefix the payload.
func (h TCPHeader) OptionsLen() int {
	words := int(h.FlagsAndHeader >> 12)
	if words <= 5 {
		return 0
	}
	return (words - 5) * 4
}

// PortOpcode returns the compact opcode used on the wire for a port pair.
func PortOpcode(src, dst uint16) Opcode {
	switch {
	case src == 1000 && dst == 1000:
		return OpTCP0
	case src >= 1000 && src <= 1255 && dst >= 1000 && dst <= 1255:
		return OpTCP1
	}
	return OpTCP2
}

func (h TCPHeader) Marshal() (Opcode, []byte) {
	op := PortOpcode(h.Src, h.Dst)
	var b []byte
	switch op {
	case OpTCP1:
		b = append(b, byte(h.Src-tcpBasePort), byte(h.Dst-tcpBasePort))
	case OpTCP2:
		b = binary.BigEndian.AppendUint16(b, h.Src)
		b = binary.BigEndian.AppendUint16(b, h.Dst)
	}
	b = binary.BigEndian.AppendUint32(b, h.Seq)
	b = binary.BigEndian.AppendUint32(b, h.Ack)
	b = binary.BigEndian.AppendUint16(b, h.FlagsAndHeader)
	b = binary.BigEndian.AppendUint16(b, h.Window)
	return op, b
}

func ParseTCPHeader(op Opcode, footer []byte) (TCPHeader, error) {
	var h TCPHeader
	if op == OpControl || len(footer) != op.FooterLen() {
		return h, ErrPacket
	}
	switch op {
	case OpTCP0:
		h.Src, h.Dst = 1000, 1000
	case OpTCP1:
		h.Src, h.Dst = tcpBasePort+uint16(footer[0]), tcpBasePort+uint16(footer[1])
		footer = footer[2:]
	case OpTCP2:
		h.Src, h.Dst = binary.BigEndian.Uint16(footer), binary.BigEndian.Uint16(footer[2:])
		footer = footer[4:]
	}
	h.Seq = binary.BigEndian.Uint32(footer)
	h.Ack = binary.BigEndian.Uint32(footer[4:])
	h.FlagsAndHeader = binary.BigEndian.Uint16(footer[8:])
	h.Window = binary.BigEndian.Uint16(footer[10:])
	return h, nil
}
