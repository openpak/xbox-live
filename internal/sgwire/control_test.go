package sgwire

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/xombie-init.hex")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
func TestPublicXombieInitFixture(t *testing.T) {
	data := fixture(t)
	init, err := ParseInit(data)
	if err != nil {
		t.Fatal(err)
	}
	if init.SPI != 0x59a300 || hex.EncodeToString(init.Nonce[:]) != "253255231a644fe4" || len(init.APReq) != 435 || len(init.SignedParameters) != 124 {
		t.Fatal("native fixture fields differ")
	}
	chunks, err := ParseChunks(data[4:])
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalChunks(chunks)
	if err != nil || !bytes.Equal(encoded, data[4:]) {
		t.Fatal("native fixture marshal differs")
	}
	for length := 0; length < len(data); length++ {
		if _, err := ParseInit(data[:length]); err == nil {
			t.Fatalf("accepted truncated packet length %d", length)
		}
	}
	for _, offset := range []int{0, 4, 6, 28, 30} {
		modified := bytes.Clone(data)
		modified[offset] ^= 0xff
		if _, err := ParseInit(modified); err == nil {
			t.Fatalf("accepted bad framing at %d", offset)
		}
	}
	if _, err := ParseInit(append(bytes.Clone(data), 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}
func TestChunkLengthUnderflowAndDuplicates(t *testing.T) {
	for _, data := range [][]byte{{2, 88, 0, 0}, {2, 88, 3, 0}, {2, 88, 255, 255}, {2, 88, 4}} {
		if _, err := ParseChunks(data); err == nil {
			t.Fatal("accepted invalid length")
		}
	}
	chunks, _ := ParseChunks(fixture(t)[4:])
	chunks = append(chunks, chunks[0])
	encoded, _ := MarshalChunks(chunks)
	if _, err := ParseInit(append(make([]byte, 4), encoded...)); err == nil {
		t.Fatal("accepted extra chunk")
	}
}
func FuzzParseInit(f *testing.F) {
	f.Add([]byte{})
	data, _ := os.ReadFile("testdata/xombie-init.hex")
	decoded, _ := hex.DecodeString(strings.TrimSpace(string(data)))
	f.Add(decoded)
	f.Fuzz(func(t *testing.T, data []byte) { ParseInit(data); ParseChunks(data) })
}
