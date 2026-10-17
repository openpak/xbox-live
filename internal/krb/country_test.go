package krb

import "testing"

func TestLocaleCode(t *testing.T) {
	for in, want := range map[string]byte{"US": 103, "us": 103, " ie ": 66} {
		if got, ok := LocaleCode(in); !ok || got != want {
			t.Fatalf("%q: %d %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "ZZ", "USA"} {
		if _, ok := LocaleCode(in); ok {
			t.Fatalf("%q must be unknown", in)
		}
	}
}
