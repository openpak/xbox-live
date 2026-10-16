// SPDX-License-Identifier: AGPL-3.0-only

package content

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"unicode/utf16"

	"openpak/xb-live/internal/xbfeature"
	"openpak/xb-live/services/xb-tou/internal/inx"
	"openpak/xb-live/services/xb-tou/internal/tou"
)

type conn struct {
	in  []byte
	out bytes.Buffer
}

func (c *conn) Recv() ([]byte, error) {
	if c.in == nil {
		return nil, io.EOF
	}
	b := c.in
	c.in = nil
	return b, nil
}
func (c *conn) Send(b []byte) error { c.out.Write(b); return nil }

func get(t *testing.T, s *tou.Server, path string) (int, []byte) {
	t.Helper()
	c := &conn{in: []byte("GET " + path + " HTTP/1.1\r\nUser-Agent: b/1.00.5849\r\nContent-type: xon/b\r\n\r\n")}
	if err := s.Serve(context.Background(), xbfeature.Info{}, c); err != nil {
		t.Fatal(err)
	}
	resp := c.out.Bytes()
	i := bytes.Index(resp, []byte("\r\n\r\n"))
	code := int(resp[9]-'0')*100 + int(resp[10]-'0')*10 + int(resp[11]-'0')
	return code, resp[i+4:]
}

func TestGeneratedSetParsesAndIsConsistent(t *testing.T) {
	for _, countries := range [][]string{{"US"}, {"IE"}, {"US", "IE"}} {
		set, err := Build(countries)
		if err != nil {
			t.Fatal(err)
		}
		srv := &tou.Server{Builtin: set}
		for _, region := range []string{"America", "Europe"} {
			code, body := get(t, srv, "/Country/"+region+"/CountryMaster2.INX")
			if code != 200 {
				t.Fatalf("master %d", code)
			}
			es, err := inx.Parse(body, true)
			if err != nil {
				t.Fatal(err)
			}
			master, err := inx.Interpret(es)
			if err != nil || inx.ValidateMaster(master) != nil || len(master) != len(countries) {
				t.Fatalf("%v %v %+v", err, inx.ValidateMaster(master), master)
			}
			for _, m := range master {
				code, body := get(t, srv, "/"+m.Name+"/CountryInfo2.INX")
				if code != 200 {
					t.Fatalf("info %s %d", m.Name, code)
				}
				es, err := inx.Parse(body, true)
				if err != nil {
					t.Fatal(err)
				}
				info, err := inx.Interpret(es)
				if err != nil || len(info) != 1 || inx.ValidateInfo(info[0], m) != nil {
					t.Fatalf("%v %+v", err, info)
				}
				for _, doc := range []string{"TermsOfUse.ini", "CodeOfConduct.ini", "PrivacyStatement.ini", "RefundInfo.ini"} {
					code, body := get(t, srv, "/"+m.Name+"/"+doc)
					if code != 200 || len(body)%2 != 0 || body[0] != 0xFF || body[1] != 0xFE {
						t.Fatalf("%s: %d (needs UTF-16LE with BOM, even length)", doc, code)
					}
					u := make([]uint16, len(body)/2-1)
					for i := range u {
						u[i] = uint16(body[2+2*i]) | uint16(body[3+2*i])<<8
					}
					txt := string(utf16.Decode(u))
					if !strings.Contains(txt, "OpenPak") && !strings.Contains(txt, "OPENPAK") {
						t.Errorf("%s does not name OpenPak", doc)
					}
					if strings.Contains(strings.ToLower(txt), "insignia") {
						t.Errorf("%s mentions another operator", doc)
					}
				}
			}
		}
	}
}

func TestOnlyConfiguredContentIs404Otherwise(t *testing.T) {
	set, _ := Build([]string{"US"})
	srv := &tou.Server{Builtin: set}
	for _, p := range []string{"/IE/CountryInfo2.INX", "/IE/TermsOfUse.ini", "/Country/Mars/CountryMaster2.INX", "/xuacs/accepttou.ashx", "/"} {
		if code, _ := get(t, srv, p); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
	if _, err := Build([]string{"ZZ"}); err == nil {
		t.Error("unknown country accepted")
	}
	if _, err := Build(nil); err == nil {
		t.Error("empty list accepted")
	}
	// without Builtin nothing is served at all
	if code, _ := get(t, &tou.Server{}, "/US/TermsOfUse.ini"); code != 404 {
		t.Errorf("no content configured: %d", code)
	}
}

func TestOperatorFilesWin(t *testing.T) {
	set, _ := Build([]string{"US"})
	dir := t.TempDir()
	srv := &tou.Server{Root: dir, Builtin: set}
	if code, _ := get(t, srv, "/US/TermsOfUse.ini"); code != 200 {
		t.Fatal("built-in not served when operator dir lacks the file")
	}
}

func TestCardTypesOptIn(t *testing.T) {
	plain, _ := Build([]string{"US"})
	if bytes.Contains(plain["/US/CountryInfo2.INX"], utf16le("CardType")) {
		t.Fatal("card types present by default")
	}
	set, err := BuildWithCardTypes([]string{"US"}, []string{"VISA"})
	if err != nil || !bytes.Contains(set["/US/CountryInfo2.INX"], utf16le("CreditCardType.CardType=\"VISA\"")) {
		t.Fatalf("%v", err)
	}
	if _, err := BuildWithCardTypes([]string{"US"}, []string{"BITCOIN"}); err == nil {
		t.Fatal("unknown card type accepted")
	}
}

func utf16le(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}
