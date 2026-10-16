// SPDX-License-Identifier: AGPL-3.0-only

// Package tou serves native service 11 (Terms of Use / country and legal
// content). The console speaks plain HTTP/1.1 over its security-gateway TCP
// connection: e.g. "GET /Country/America/CountryMaster2.INX" with
// "Content-type: xon/b". Content is served only from an operator-supplied
// directory (the INX files are not synthesised here); anything absent is a
// plain 404, anything that is not a GET is a 405.
package tou

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"openpak/xb-live/internal/xbfeature"
)

const maxFile = 4 << 20

// Server implements xbfeature.Handler.
type Server struct {
	// Root is the content directory; request paths map below it.
	Root string
}

type connReader struct {
	c   xbfeature.Conn
	buf []byte
}

func (r *connReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		b, err := r.c.Recv()
		if err != nil {
			return 0, err
		}
		r.buf = b
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Serve handles keep-alive HTTP requests until the console closes.
func (s *Server) Serve(_ context.Context, _ xbfeature.Info, c xbfeature.Conn) error {
	br := bufio.NewReaderSize(&connReader{c: c}, 8<<10)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return s.respond(c, nil, 400, "Bad Request", true)
		}
		io.Copy(io.Discard, io.LimitReader(req.Body, 1<<20))
		req.Body.Close()
		code, body := s.lookup(req)
		close := req.Close || req.ProtoMajor == 1 && req.ProtoMinor == 0 || code >= 400
		if err := s.respond(c, req, code, body, close); err != nil || close {
			return err
		}
	}
}

func (s *Server) lookup(req *http.Request) (int, string) {
	if req.Method != http.MethodGet {
		return 405, "Method Not Allowed"
	}
	clean := path.Clean("/" + req.URL.Path)
	if s.Root == "" || strings.ContainsRune(clean, 0) {
		return 404, "Not Found"
	}
	f := filepath.Join(s.Root, filepath.FromSlash(clean))
	st, err := os.Stat(f)
	if err != nil || !st.Mode().IsRegular() {
		return 404, "Not Found"
	}
	if st.Size() > maxFile {
		return 500, "Internal Server Error"
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return 500, "Internal Server Error"
	}
	return 200, string(b)
}

func (s *Server) respond(c xbfeature.Conn, req *http.Request, code int, body string, close bool) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n", code, http.StatusText(code), len(body))
	if code == 200 {
		b.WriteString("Content-Type: application/octet-stream\r\n")
	} else {
		b.WriteString("Content-Type: text/plain\r\n")
	}
	if close {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	if req == nil || req.Method != http.MethodHead {
		b.WriteString(body)
	}
	out := b.Bytes()
	for len(out) > 0 { // keep each frame well under the transport limit
		n := min(len(out), 16<<10)
		if err := c.Send(out[:n]); err != nil {
			return err
		}
		out = out[n:]
	}
	return nil
}
