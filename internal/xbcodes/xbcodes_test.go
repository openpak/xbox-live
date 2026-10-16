// SPDX-License-Identifier: AGPL-3.0-only

package xbcodes

import (
	"strings"
	"testing"
)

func TestAlphabet(t *testing.T) {
	if len(Alphabet) != 32 || strings.ContainsAny(Alphabet, "IO01") {
		t.Fatal("alphabet must be 32 symbols without I, O, 0, 1")
	}
}

func TestGenerateAndNormalize(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := NewPairing()
		if err != nil || len(p) != 8 {
			t.Fatal(err, p)
		}
		if n, ok := NormalizePairing(strings.ToLower(FormatPairing(p))); !ok || n != p {
			t.Fatalf("pairing round trip %q -> %q", p, n)
		}
		v, _ := NewVoucher()
		if n, ok := NormalizeVoucher(" " + strings.ToLower(FormatVoucher(v)) + " "); !ok || n != v || seen[v] {
			t.Fatalf("voucher round trip %q -> %q", v, n)
		}
		seen[v] = true
		for _, c := range v {
			if !strings.ContainsRune(Alphabet, c) {
				t.Fatalf("symbol %q outside the alphabet", c)
			}
		}
	}
}

func TestNormalizeRejects(t *testing.T) {
	for _, s := range []string{"", "ABCDEFG", "ABCDEFGHJ", "ABCDEFG0", "ABCDEFGI", "ABCD\x00EFG", "ABCD_EFG", strings.Repeat("A", 100)} {
		if _, ok := NormalizePairing(s); ok {
			t.Errorf("pairing %q accepted", s)
		}
	}
	for _, s := range []string{"", strings.Repeat("A", 24), strings.Repeat("A", 26), strings.Repeat("A", 24) + "O", strings.Repeat("A", 500)} {
		if _, ok := NormalizeVoucher(s); ok {
			t.Errorf("voucher %q accepted", s)
		}
	}
}
