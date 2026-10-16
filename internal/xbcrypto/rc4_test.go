package xbcrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func key(t *testing.T, value string) Key {
	t.Helper()
	var result Key
	decoded := unhex(t, value)
	if len(decoded) != 16 {
		t.Fatal("invalid test key")
	}
	copy(result[:], decoded)
	return result
}

// Public Xombie source fixtures, not user-supplied dumps or live credentials.
func TestXombieCipherFixture(t *testing.T) {
	k := key(t, "b274d292fe16a0175870db617b02d0ad")
	plaintext := unhex(t, "301aa011180f32303230303431353033313735325aa10502030e9a48")
	confounder := [8]byte{0x2a, 0x8c, 0xe4, 0xf6, 0xfb, 0x24, 0x10, 0x0e}
	expected := unhex(t, "b22311a86ed613726b22d18a8911338a113fdca1f103a8484093fb5f23978bb38acccfd4de8236b598737fd78dea4b0c318eb347")
	actual, err := seal(k, 1, plaintext, confounder)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("fixture mismatch: %v", err)
	}
	decoded, err := Open(k, 1, expected)
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatal("could not open fixture")
	}
	for index := range expected {
		modified := bytes.Clone(expected)
		modified[index] ^= 1
		if _, err := Open(k, 1, modified); err == nil {
			t.Fatalf("accepted tampering at %d", index)
		}
	}
	if _, err := Open(k, 2, expected); err == nil {
		t.Fatal("accepted wrong key usage")
	}
	for length := 0; length < 24; length++ {
		if _, err := Open(k, 1, expected[:length]); err == nil {
			t.Fatal("accepted truncation")
		}
	}
}
func TestXombieDerivationFixtures(t *testing.T) {
	hdd := key(t, "f8d4863cac0eda58813b7a6d4a7eb4a3")
	online := key(t, "1c3ca4bb85a4b258a0a63a14978ca055")
	if MachineKey(hdd, online) != key(t, "adab552ff9e45e479c7f924619e962bd") {
		t.Fatal("machine key fixture mismatch")
	}
	if NonceKey(key(t, "b274d292fe16a0175870db617b02d0ad"), 0) != key(t, "2a6bade51ff5dd3f77de26ed2b2a8a62") {
		t.Fatal("nonce fixture mismatch")
	}
	if NonceKey(key(t, "755d72fc34c493901ea6e8e3dd3fab75"), 0x0b9bd8d3) != key(t, "d85ef7e89018effbb5bbb9c3cdcbfc95") {
		t.Fatal("nonce fixture mismatch")
	}
}
func FuzzOpen(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 24))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			t.Skip()
		}
		Open(Key{}, 1, data)
	})
}
