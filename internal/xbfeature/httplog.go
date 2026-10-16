// SPDX-License-Identifier: AGPL-3.0-only

package xbfeature

import (
	"bytes"
	"context"
	"log"
	"strconv"
	"strings"
	"time"
)

// LogHTTP wraps h so every HTTP request/response pair on a console connection
// produces one log line: service id, connection generation, method, path (no
// query), HTTP status, X-Err and duration. It never records bodies, headers
// other than X-Err, identities or tickets. Both directions are only inspected
// for the first line / header block of each message.
func LogHTTP(h Handler) Handler { return logged{h} }

type logged struct{ h Handler }

func (l logged) Serve(ctx context.Context, info Info, c Conn) error {
	lc := &logConn{Conn: c, info: info}
	err := l.h.Serve(ctx, info, lc)
	if lc.pending {
		log.Printf("xbfeature svc=%d gen=%d req=%q ended without a response (head %d bytes, err=%v)",
			info.ServiceID, info.Generation, lc.line, len(lc.head), err != nil)
	}
	return err
}

type logConn struct {
	Conn
	info    Info
	head    []byte // request bytes until the first line is complete
	line    string
	start   time.Time
	pending bool
}

func (c *logConn) Recv() ([]byte, error) {
	b, err := c.Conn.Recv()
	if len(b) > 0 && !c.pending {
		if c.head == nil {
			c.start = time.Now()
		}
		if len(c.head) < 1024 {
			c.head = append(c.head, b[:min(len(b), 1024-len(c.head))]...)
		}
		if i := bytes.Index(c.head, []byte("\r\n")); i >= 0 || len(c.head) >= 1024 {
			if i < 0 {
				i = len(c.head)
			}
			c.line, c.pending = requestLine(string(c.head[:i])), true
		}
	}
	return b, err
}

func (c *logConn) Send(b []byte) error {
	if c.pending {
		status, xerr := responseHead(b)
		log.Printf("xbfeature svc=%d gen=%d req=%q status=%s xerr=%s dur=%s",
			c.info.ServiceID, c.info.Generation, c.line, status, xerr, time.Since(c.start).Round(time.Millisecond))
		c.pending, c.head, c.line = false, nil, ""
	}
	return c.Conn.Send(b)
}

// requestLine reduces "POST /a/b?x=1 HTTP/1.0" to "POST /a/b", printable ASCII only.
func requestLine(s string) string {
	f := strings.Fields(s)
	if len(f) < 2 {
		return "?"
	}
	p, _, _ := strings.Cut(f[1], "?")
	clean := func(v string) string {
		return strings.Map(func(r rune) rune {
			if r < 0x21 || r > 0x7e {
				return '_'
			}
			return r
		}, v)
	}
	out := clean(f[0]) + " " + clean(p)
	return out[:min(len(out), 96)]
}

// responseHead extracts the HTTP status code and X-Err value from a response.
func responseHead(b []byte) (status, xerr string) {
	status, xerr = "?", "-"
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		end = min(len(b), 1024)
	}
	lines := strings.Split(string(b[:min(end, 1024)]), "\r\n")
	if f := strings.Fields(lines[0]); len(f) >= 2 {
		if n, err := strconv.Atoi(f[1]); err == nil {
			status = strconv.Itoa(n)
		}
	}
	for _, ln := range lines[1:] {
		if k, v, ok := strings.Cut(ln, ":"); ok && strings.EqualFold(k, "X-Err") {
			v = strings.TrimSpace(v)
			if len(v) <= 16 && strings.Trim(v, "0123456789abcdefABCDEF") == "" {
				xerr = strings.ToLower(v)
			}
		}
	}
	return
}
