// SPDX-License-Identifier: AGPL-3.0-only

package xbfeature

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"
	"testing"
)

type fakeConn struct {
	in  [][]byte
	out [][]byte
}

func (f *fakeConn) Recv() ([]byte, error) {
	if len(f.in) == 0 {
		return nil, io.EOF
	}
	b := f.in[0]
	f.in = f.in[1:]
	return b, nil
}
func (f *fakeConn) Send(b []byte) error { f.out = append(f.out, b); return nil }

type echo struct{}

func (echo) Serve(_ context.Context, _ Info, c Conn) error {
	for {
		if _, err := c.Recv(); err != nil {
			return nil
		}
		if err := c.Send([]byte("HTTP/1.0 200 OK\r\nX-Err: 80154007\r\nContent-Length: 2\r\n\r\nzz")); err != nil {
			return err
		}
	}
}

func TestLogHTTPOneLinePerRequestNoBody(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(io.Discard)
	c := &fakeConn{in: [][]byte{
		[]byte("POST /xuacs/verifyvoucher.ashx?q=SECRET HTTP/1.0\r\nContent-type: xon/5\r\n\r\n"),
		[]byte("ABCDE-SECRETCODE"),
	}}
	if err := LogHTTP(echo{}).Serve(context.Background(), Info{ServiceID: 5, Generation: 7}, c); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, `svc=5 gen=7 req="POST /xuacs/verifyvoucher.ashx" status=200 xerr=80154007`) {
		t.Fatalf("log: %q", out)
	}
	if strings.Contains(out, "SECRET") || len(c.out) != 2 {
		t.Fatalf("leak or passthrough broken: %q %d", out, len(c.out))
	}
}
