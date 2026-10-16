// SPDX-License-Identifier: AGPL-3.0-only
package xbdns

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func q(name string, qtype, class uint16, mut func([]byte) []byte) []byte {
	b := []byte{0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), byte(class>>8), byte(class))
	if mut != nil {
		b = mut(b)
	}
	return b
}

func tbl(t *testing.T) Table {
	tb, err := BuildTable("203.0.113.9", "")
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestExactNames(t *testing.T) {
	tb := tbl(t)
	for _, n := range AuthNames {
		r, rc, hit := tb.Answer(q(strings.ToUpper(n), 1, 1, nil))
		if !hit || rc != 0 || r[len(r)-1] != 9 || r[7] != 1 {
			t.Fatalf("%s: %v %d", n, r, rc)
		}
	}
}

func TestNotCaptured(t *testing.T) {
	tb := tbl(t)
	for _, n := range []string{"xboxlive.com", "foo.xboxlive.com", "as.xboxlive.com.evil.net", "xbox.as.xboxlive.com",
		"auth.xbox.live.com", "user.auth.xboxlive.com", "example.com", "x.as.part.xboxlive.com"} {
		r, rc, hit := tb.Answer(q(n, 1, 1, nil))
		if hit || rc != RcodeNXDomain || r[7] != 0 {
			t.Fatalf("%s leaked: rc=%d", n, rc)
		}
	}
}

func TestOtherTypeClassOpcode(t *testing.T) {
	tb := tbl(t)
	r, rc, _ := tb.Answer(q("as.xboxlive.com", 28, 1, nil)) // AAAA -> NODATA
	if rc != 0 || r[7] != 0 {
		t.Fatal("aaaa")
	}
	if _, rc, _ := tb.Answer(q("as.xboxlive.com", 1, 3, nil)); rc != RcodeRefused {
		t.Fatal("chaos")
	}
	if _, rc, _ := tb.Answer(q("as.xboxlive.com", 1, 1, func(b []byte) []byte { b[2] |= 0x28; return b })); rc != RcodeNotImp {
		t.Fatal("opcode")
	}
}

func TestMalformed(t *testing.T) {
	tb := tbl(t)
	good := q("as.xboxlive.com", 1, 1, nil)
	if r, _, _ := tb.Answer(good[:5]); r != nil {
		t.Fatal("short")
	}
	if r, _, _ := tb.Answer(make([]byte, MaxQuery+1)); r != nil {
		t.Fatal("oversize")
	}
	if r, _, _ := tb.Answer(q("as.xboxlive.com", 1, 1, func(b []byte) []byte { b[2] |= 0x80; return b })); r != nil {
		t.Fatal("response must be dropped")
	}
	for _, bad := range [][]byte{
		good[:len(good)-3],
		q("as.xboxlive.com", 1, 1, func(b []byte) []byte { b[5] = 2; return b }),          // qdcount 2
		q("as.xboxlive.com", 1, 1, func(b []byte) []byte { b[7] = 1; return b }),          // ancount in query
		append(append([]byte{}, good[:12]...), 0xc0, 0x0c, 0, 1, 0, 1),                    // compression pointer
		append(append([]byte{}, good[:12]...), 64, 'a'),                                   // label too long/truncated
		append(append([]byte{}, good[:12]...), append(make([]byte, 0), 0, 0, 1, 0, 1)...), // root name
	} {
		r, rc, hit := tb.Answer(bad)
		if hit || r == nil || rc != RcodeFormErr || r[7] != 0 {
			t.Fatalf("bad packet accepted: rc=%d", rc)
		}
	}
}

func TestTableFile(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := dir + "/t"
		if err := writeFile(p, s); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := BuildTable("", write("*.xboxlive.com 203.0.113.1\n")); err == nil {
		t.Fatal("wildcard/unknown name accepted")
	}
	if _, err := BuildTable("", write("as.xboxlive.com 127.0.0.1\n")); err == nil {
		t.Fatal("loopback accepted")
	}
	if _, err := BuildTable("", write("xbox360.live.com 203.0.113.1\n")); err == nil {
		t.Fatal("360 name accepted")
	}
	tb, err := BuildTable("203.0.113.9", write("# c\nTGS.xboxlive.com. 203.0.113.2\n"))
	if err != nil || tb["tgs.xboxlive.com"] != netip.MustParseAddr("203.0.113.2") || len(tb) != 6 {
		t.Fatal(err, tb)
	}
	if _, err := BuildTable("", ""); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(1, 2, 2)
	now := time.Unix(1000, 0)
	a := netip.MustParseAddr("192.0.2.1")
	if !l.Allow(a, now) || !l.Allow(a, now) || l.Allow(a, now) {
		t.Fatal("burst")
	}
	if !l.Allow(a, now.Add(2*time.Second)) {
		t.Fatal("refill")
	}
	l.Allow(netip.MustParseAddr("192.0.2.2"), now)
	if l.Allow(netip.MustParseAddr("192.0.2.3"), now) {
		t.Fatal("table bound")
	}
}

func TestServeUDP(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	s := &Server{Table: tbl(t), Lim: NewLimiter(100, 100, 10)}
	go s.Serve(c)
	defer c.Close()
	cl, _ := net.Dial("udp", c.LocalAddr().String())
	defer cl.Close()
	cl.SetDeadline(time.Now().Add(2 * time.Second))
	cl.Write(q("macs.xboxlive.com", 1, 1, nil))
	buf := make([]byte, 512)
	n, err := cl.Read(buf)
	if err != nil || buf[n-1] != 9 {
		t.Fatal(err)
	}
	if s.C.Answered.Load() != 1 {
		t.Fatal("counter")
	}
}

func FuzzAnswer(f *testing.F) {
	tb := Table{"as.xboxlive.com": netip.MustParseAddr("203.0.113.9")}
	f.Add(q("as.xboxlive.com", 1, 1, nil))
	f.Add(q("a.b", 255, 1, nil))
	f.Add([]byte{})
	f.Add(append(make([]byte, 12), 0xc0, 0x0c))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, _, _ := tb.Answer(b)
		if r != nil && len(r) > MaxQuery {
			t.Fatal("amplification")
		}
	})
}
