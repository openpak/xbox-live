// SPDX-License-Identifier: AGPL-3.0-only

package tou

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openpak/xb-live/internal/xbfeature"
)

// capturedGET is the first request the stock 5960 dashboard sent after SG
// connect (service 11), captured from the gateway's decrypted stream.
const capturedGET = "GET /Country/America/CountryMaster2.INX HTTP/1.1\r\nUser-Agent: b/1.00.5849\r\nContent-type: xon/b\r\nHost: 0.197.81.0\r\n\r\n"

type fakeConn struct {
	in  [][]byte
	out bytes.Buffer
}

func (f *fakeConn) Recv() ([]byte, error) {
	if len(f.in) == 0 {
		return nil, io.EOF
	}
	b := f.in[0]
	f.in = f.in[1:]
	return b, nil
}
func (f *fakeConn) Send(b []byte) error { f.out.Write(b); return nil }

func run(t *testing.T, s *Server, chunks ...string) string {
	t.Helper()
	c := &fakeConn{}
	for _, ch := range chunks {
		c.in = append(c.in, []byte(ch))
	}
	if err := s.Serve(context.Background(), xbfeature.Info{XUID: 1}, c); err != nil {
		t.Fatal(err)
	}
	return c.out.String()
}

func TestCapturedRequestWithoutContentIs404(t *testing.T) {
	got := run(t, &Server{Root: t.TempDir()}, capturedGET)
	if !strings.HasPrefix(got, "HTTP/1.1 404 Not Found\r\n") || !strings.HasSuffix(got, "\r\n\r\nNot Found") {
		t.Fatalf("%q", got)
	}
}

func TestServesOperatorContentAndSplitReads(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Country", "America")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "CountryMaster2.INX"), []byte("INX-BYTES"), 0o644)
	// the request arrives split across TCP segments
	got := run(t, &Server{Root: root}, capturedGET[:30], capturedGET[30:])
	if !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") || !strings.Contains(got, "Content-Length: 9\r\n") || !strings.HasSuffix(got, "\r\n\r\nINX-BYTES") {
		t.Fatalf("%q", got)
	}
}

func TestKeepAliveTraversalAndMethods(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a"), []byte("A"), 0o644)
	req := func(m, p string) string { return m + " " + p + " HTTP/1.1\r\nHost: x\r\n\r\n" }
	got := run(t, &Server{Root: root}, req("GET", "/a")+req("GET", "/a"))
	if strings.Count(got, "HTTP/1.1 200 OK") != 2 {
		t.Fatalf("keep-alive: %q", got)
	}
	if got := run(t, &Server{Root: root}, req("GET", "/../../etc/passwd")); !strings.Contains(got, " 404 ") {
		t.Fatalf("traversal: %q", got)
	}
	if got := run(t, &Server{Root: root}, req("POST", "/a")); !strings.Contains(got, " 405 ") {
		t.Fatalf("method: %q", got)
	}
	if got := run(t, &Server{Root: root}, "garbage\r\n\r\n"); !strings.Contains(got, " 400 ") {
		t.Fatalf("garbage: %q", got)
	}
}

func TestBuiltinFallbackAndOperatorPrecedence(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a"), []byte("OPERATOR"), 0o644)
	s := &Server{Root: root, Builtin: map[string][]byte{"/a": []byte("BUILTIN"), "/b": []byte("BUILTIN-B")}}
	req := func(p string) string { return "GET " + p + " HTTP/1.1\r\nHost: x\r\n\r\n" }
	if got := run(t, s, req("/a")); !strings.HasSuffix(got, "OPERATOR") {
		t.Fatalf("operator must win: %q", got)
	}
	if got := run(t, s, req("/b")); !strings.HasSuffix(got, "BUILTIN-B") {
		t.Fatalf("builtin fallback: %q", got)
	}
	if got := run(t, s, req("/c")); !strings.Contains(got, " 404 ") {
		t.Fatalf("absent: %q", got)
	}
	if got := run(t, &Server{Builtin: s.Builtin}, req("/b")); !strings.HasSuffix(got, "BUILTIN-B") {
		t.Fatalf("builtin without Root: %q", got)
	}
}
