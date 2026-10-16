// SPDX-License-Identifier: AGPL-3.0-only

package inx

import (
	"strings"
	"testing"
	"unicode/utf16"
)

func u16(s string) []byte { // raw UTF-16LE without adding a BOM
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}
func file(s string) []byte { return append([]byte{0xFF, 0xFE}, u16(s)...) }

func TestGrammarQuirks(t *testing.T) {
	src := "[US]\r\nLocaleCode = \"103\" ; trailing comment\r\n# whole line\r\nDate Sep\"arator\"=\"/\"\r\nBare\r\n[ I E ]\r\nX=\"a b;c\"\r\n"
	es, err := Parse(file(src), true)
	if err == nil {
		t.Fatalf("misplaced quote inside an ID must fail, got %v", es)
	}
	src = "[US]\r\nLocaleCode = \"103\" ; trailing comment\r\n# whole line\r\nDate Separator=\"/\"\r\nBare\r\n[ I E ]\r\nX=\"a b;c\"\r\n"
	es, err = Parse(file(src), true)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"US", "LocaleCode", "103", 2}, {"US", "DateSeparator", "/", 4}, {"US", "Bare", "", 5}, {" I E ", "X", "a b;c", 7}}
	if len(es) != len(want) {
		t.Fatalf("%+v", es)
	}
	for i := range want {
		if es[i] != want[i] {
			t.Errorf("%d: %+v want %+v", i, es[i], want[i])
		}
	}
}

func TestSyntaxErrors(t *testing.T) {
	long := strings.Repeat("a", MaxName+1)
	for name, src := range map[string][]byte{
		"no BOM":             u16("[US]\r\n"),
		"odd length":         append(file("[US]\r\n"), 0),
		"CR in string":       file("[US]\r\nA=\"x\r\ny\"\r\n"),
		"CR in section":      file("[US\r\n]\r\n"),
		"value not quoted":   file("[US]\r\nA=1\r\n"),
		"ID too long":        file("[US]\r\n" + long + "=\"1\"\r\n"),
		"section too long":   file("[" + long + "]\r\n"),
		"string too long":    file("[US]\r\nA=\"" + strings.Repeat("x", MaxValue+1) + "\"\r\n"),
		"unterminated value": file("[US]\r\nA=\"x"),
	} {
		if _, err := Parse(src, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse(file("[US]\r\nA=\""+strings.Repeat("x", MaxValue)+"\"\r\n"), true); err != nil {
		t.Errorf("max-length string rejected: %v", err)
	}
}

func TestWriterRoundTripAndRefusals(t *testing.T) {
	w := NewWriter()
	w.Comment("hi")
	if err := w.Section("US"); err != nil {
		t.Fatal(err)
	}
	if err := w.Set("A", "x y;z#"); err != nil {
		t.Fatal(err)
	}
	es, err := Parse(w.Bytes(), true)
	if err != nil || len(es) != 1 || es[0].Value != "x y;z#" {
		t.Fatalf("%v %+v", err, es)
	}
	for _, id := range []string{"", "a b", "a=b", "a\"b", "a;b"} {
		if w.Set(id, "v") == nil {
			t.Errorf("ID %q accepted", id)
		}
	}
	if w.Set("A", "has\"quote") == nil || w.Set("A", "cr\r") == nil {
		t.Error("unquotable value accepted")
	}
}

func TestInterpretAndValidate(t *testing.T) {
	es, _ := Parse(file("[us]\r\nLocaleCode=\"103\"\r\n[US]\r\nPostalCode.Min=\"5\"\r\nDayPosition=\"1\"\r\nMonthPosition=\"0\"\r\nYearPosition=\"2\"\r\nDateSeparator=\"/\"\r\n"), true)
	cs, err := Interpret(es)
	if err != nil || len(cs) != 1 { // section names match case-insensitively
		t.Fatalf("%v %+v", err, cs)
	}
	if cs[0].LocaleCode != 103 || cs[0].Fields["PostalCode"]["Min"] != "5" {
		t.Fatalf("%+v", cs[0])
	}
	if err := ValidateInfo(cs[0], &Country{Name: "US", LocaleCode: 103}); err != nil {
		t.Fatal(err)
	}
	if ValidateInfo(cs[0], &Country{Name: "US", LocaleCode: 9}) == nil {
		t.Error("locale mismatch accepted")
	}
	if ValidateMaster([]*Country{{Name: "US", LocaleCode: 0}}) == nil {
		t.Error("zero locale accepted")
	}
	if _, err := Interpret([]Entry{{"US", "Bogus", "1", 1}}); err == nil {
		t.Error("unknown ID accepted")
	}
}
