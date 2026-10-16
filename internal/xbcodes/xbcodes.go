// SPDX-License-Identifier: AGPL-3.0-only

// Package xbcodes generates and normalises the two human-typed codes of the
// enrolment flow: the 8-character device pairing code shown on a console, and
// the 25-character subscription code typed into the dashboard (5x5 groups).
// Both use a 32-symbol uppercase alphanumeric alphabet without the look-alikes
// I, O, 0 and 1, and are compared case-insensitively: input is upper-cased and
// separators are stripped before it is checked or hashed.
package xbcodes

import "crypto/rand"

// Alphabet has exactly 32 symbols, so a masked random byte is unbiased.
const Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

const (
	PairingLen = 8
	VoucherLen = 25
)

func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = Alphabet[b[i]&31]
	}
	return string(b), nil
}

// NewPairing returns a fresh 8-character pairing code (40 bits).
func NewPairing() (string, error) { return random(PairingLen) }

// NewVoucher returns a fresh 25-character subscription code (125 bits).
func NewVoucher() (string, error) { return random(VoucherLen) }

func normalize(s string, n int, strip string) (string, bool) {
	if len(s) > 4*n { // bound work on hostile input
		return "", false
	}
	out := make([]byte, 0, n)
	for i := 0; i < len(s); i++ {
		c := s[i]
		skip := false
		for j := 0; j < len(strip); j++ {
			if c == strip[j] {
				skip = true
			}
		}
		if skip {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		ok := false
		for j := 0; j < len(Alphabet); j++ {
			if Alphabet[j] == c {
				ok = true
			}
		}
		if !ok || len(out) == n {
			return "", false
		}
		out = append(out, c)
	}
	return string(out), len(out) == n
}

// NormalizePairing canonicalises a typed pairing code (spaces and '-' ignored).
func NormalizePairing(s string) (string, bool) { return normalize(s, PairingLen, " -") }

// NormalizeVoucher canonicalises a typed subscription code. The dashboard
// strips spaces, '-' and '.' before it counts 25 characters; so do we.
func NormalizeVoucher(s string) (string, bool) { return normalize(s, VoucherLen, " -.") }

// FormatPairing groups a canonical pairing code as XXXX-XXXX for display.
func FormatPairing(c string) string { return c[:4] + "-" + c[4:] }

// FormatVoucher groups a canonical subscription code as five groups of five.
func FormatVoucher(c string) string {
	return c[0:5] + "-" + c[5:10] + "-" + c[10:15] + "-" + c[15:20] + "-" + c[20:25]
}
