// SPDX-License-Identifier: AGPL-3.0-only
package sgwire

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func h(s string) []byte {
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		panic(err)
	}
	return b
}
func a8(s string) (o [8]byte)   { copy(o[:], h(s)); return }
func a16(s string) (o [16]byte) { copy(o[:], h(s)); return }
func a24(s string) (o [24]byte) { copy(o[:], h(s)); return }
func a96(s string) (o [96]byte) { copy(o[:], h(s)); return }

// Vectors from Xombie libs/xblive/src/crypto/derivation.rs.
func TestDeriveKeysXombieVector(t *testing.T) {
	k := DeriveKeys(a16("313359b8acb344b9981e6be2c55fb51c"),
		a96("953419df3ffe6ddaca2a09bd4a4b968f84eda87c602d84aa16905cd1c9b247de566e7754e81e14a9b149ce33c77cf363c7c8c3cb3090952760bcc776f98b13e5450abd3a73122fe430ba32b0b2cf126ee703ee5c42fad6d8c6e4c58406643b49"),
		a8("7f53f5dedee88297"), a8("1d8744408c89b113"))
	want := ConnectionKeys{
		SGToClient: OneWayKeys{a16("DA0C47814D995775248259D2730B0082"), a24("BC9DE0D576C4AD58BA31203275527A3DF8D3808AF258CDEF"), a8("E12578D975D33725")},
		ClientToSG: OneWayKeys{a16("D4D3244F962CB851F7E6DA571FB03E2A"), a24("52102FD04CE6C210138C855BE0080D2AF7D561F25210A20B"), a8("64A65895AB73D84E")},
	}
	// Parity bits are irrelevant to Go's DES; compare ignoring the low bit of DES key bytes.
	mask := func(d [24]byte) (o [24]byte) {
		for i := range d {
			o[i] = d[i] &^ 1
		}
		return
	}
	if k.SGToClient.SHA != want.SGToClient.SHA || k.ClientToSG.SHA != want.ClientToSG.SHA ||
		k.SGToClient.IV != want.SGToClient.IV || k.ClientToSG.IV != want.ClientToSG.IV ||
		mask(k.SGToClient.DES) != mask(want.SGToClient.DES) || mask(k.ClientToSG.DES) != mask(want.ClientToSG.DES) {
		t.Fatalf("key schedule differs: %x", k)
	}
}

var vecA = OneWayKeys{
	SHA: a16("e25fa92ac90fcb43874556f1dfffb972"),
	DES: a24("b368648c9b2031837f1fa7708352d39bb952b66de507b508"),
	IV:  a8("50240bfec6c78c00"),
}

// Captured Xombie client packets (packet.rs tests).
func TestOpenXombieCapturedPackets(t *testing.T) {
	syn := h("83010000 f80d251151fc2fcd 0b7fa52b00000000 60024238 0600 f0d19e5e57f31fc7b754")
	p, err := Open(syn, vecA, 5)
	if err != nil || p.Seq != 6 || p.Opcode != OpTCP2 || len(p.Payload) != 4 {
		t.Fatalf("syn: %v %+v", err, p)
	}
	ack := h("03010000 04000069 0b7fa52c d3d57cad 50104238 0700 5f71ae59168f01b2c8d2")
	p, err = Open(ack, vecA, 6)
	if err != nil || p.Seq != 7 || len(p.Payload) != 0 || len(p.Footer) != 16 {
		t.Fatalf("ack: %v %+v", err, p)
	}
	if _, err := Open(syn, vecA, 0x20000); err == nil {
		t.Fatal("accepted a packet with a different sequence epoch")
	}
	bad := bytes.Clone(syn)
	bad[10] ^= 1
	if _, err := Open(bad, vecA, 5); err != ErrAuth {
		t.Fatalf("tampered packet accepted: %v", err)
	}
}

func TestSealMatchesXombieVector(t *testing.T) {
	keys := OneWayKeys{
		SHA: a16("e6d853033f46f8acdb10b41663aec4db"),
		DES: a24("a7cbd3fed60846ba4fc1ae67e3e0f4d5a7f1e0b9922304b9"),
		IV:  a8("66e326691126dc23"),
	}
	payload := h(`485454502f312e3020323030204f4b0d
		0a436f6e74656e742d4c656e6774683a
		2034380d0a436f6e74656e742d547970
		653a20786f6e2f310d0a582d45727 23a
		20300d0a0d0a`)
	footer := h("00650404fdecf8a330b9ad495018ffff")
	want := h(`4314b400c9b919dd8a3d6040c849868e 88e9bc799bb74b750c94f7de8993f8a0
		2ba2e8fbc90396a80740f371d27412e4 a321f81c1fbaf62b96fbd4b037eddd5c
		2b0c5dc50a4b53f3899507bd0404fdec f8a330b9ad4950 18ffff0200d453e33c
		f4ea14d6b1f2`)
	got, err := Seal(keys, OpTCP2, SPI{20, 180, 0}, 2, payload, footer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("sealed bytes differ from Xombie vector:\n%x\n%x", got, want)
	}
	p, err := Open(got, keys, 1)
	if err != nil || !bytes.Equal(p.Payload, payload) || !bytes.Equal(p.Footer, footer) || p.Seq != 2 {
		t.Fatalf("round trip: %v", err)
	}
}

func TestSealOpenRoundTripAllShapes(t *testing.T) {
	var keys OneWayKeys
	rand.Read(keys.SHA[:])
	rand.Read(keys.DES[:])
	rand.Read(keys.IV[:])
	for _, op := range []Opcode{OpControl, OpTCP0, OpTCP1, OpTCP2} {
		for n := 0; n < 40; n++ {
			payload := make([]byte, n)
			rand.Read(payload)
			footer := make([]byte, op.FooterLen())
			rand.Read(footer)
			for _, seq := range []uint32{1, 0xffff, 0x10000, 0x1ffff} {
				pkt, err := Seal(keys, op, SPI{1, 2, 3}, seq, payload, footer)
				if err != nil {
					t.Fatal(err)
				}
				p, err := Open(pkt, keys, seq-1)
				if err != nil || p.Seq != seq || !bytes.Equal(p.Payload, payload) || !bytes.Equal(p.Footer, footer) {
					t.Fatalf("op %d n %d seq %d: %v", op, n, seq, err)
				}
			}
		}
	}
	if _, err := Seal(keys, OpControl, SPI{1, 0, 0}, 0, nil, nil); err == nil {
		t.Fatal("sealed sequence 0")
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	var keys OneWayKeys
	for n := 0; n < 200; n++ {
		b := make([]byte, n)
		rand.Read(b)
		if _, err := Open(b, keys, 0); err == nil {
			t.Fatal("accepted random packet")
		}
	}
}

func TestReplayWindow(t *testing.T) {
	var w ReplayWindow
	for _, c := range []struct {
		seq uint32
		ok  bool
	}{{1, true}, {1, false}, {5, true}, {3, true}, {3, false}, {5, false}, {200, true}, {5, false}, {150, true}, {150, false}, {137, true}, {136, false}} {
		if w.Accept(c.seq) != c.ok {
			t.Fatalf("seq %d expected %v", c.seq, c.ok)
		}
	}
}

func TestDHAgreementAndValidation(t *testing.T) {
	a, apub, err := GenerateDH(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, bpub, _ := GenerateDH(nil)
	sa, err1 := a.Secret(bpub[:])
	sb, err2 := b.Secret(apub[:])
	if err1 != nil || err2 != nil || sa != sb {
		t.Fatal("DH disagreement")
	}
	_, apub2, _ := GenerateDH(nil)
	if apub == apub2 {
		t.Fatal("DH public values repeat")
	}
	for _, bad := range [][]byte{make([]byte, 96), append([]byte{1}, make([]byte, 95)...), bytes.Repeat([]byte{0xff}, 96), make([]byte, 95)} {
		if _, err := a.Secret(bad); err == nil {
			t.Fatal("accepted degenerate DH value")
		}
	}
}

func TestInitResponseShape(t *testing.T) {
	var r InitResponse
	r.GatewaySPI, r.ClientSPI = 0x112200, 0x59a300
	r.ClientIP, r.ClientPort, r.XUID = [4]byte{192, 0, 2, 9}, 3074, 0x0123456789abcdef
	called := false
	out, err := BuildInitResponse(r, [16]byte{1}, func(sub []byte) ([]byte, error) { called = len(sub) == 20; return []byte{1, 2, 3}, nil })
	if err != nil || !called {
		t.Fatal(err)
	}
	chunks, err := ParseChunks(out[4:])
	if err != nil || len(chunks) != 3 || chunks[0].Tag != TagResponse || chunks[1].Tag != TagDH || chunks[2].Tag != TagAPRep || len(chunks[0].Data) != 60 {
		t.Fatalf("shape: %v %d", err, len(chunks))
	}
	if chunks[0].Data[4] != 0 || chunks[0].Data[5] != 0xa3 || chunks[0].Data[6] != 0x59 {
		t.Fatal("client SPI not echoed")
	}
}

func TestSPIConversions(t *testing.T) {
	if s := SPIFromU32(0x59a300); s != (SPI{0xa3, 0x59, 0}) || s.U32() != 0x59a300 {
		t.Fatal(s)
	}
}
