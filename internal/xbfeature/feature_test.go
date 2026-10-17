// SPDX-License-Identifier: AGPL-3.0-only

package xbfeature

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type pki struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPool *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca, k, pool}
}

func (p *pki) leaf(t *testing.T, uri string, server bool) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(uri)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"}, URIs: []*url.URL{u},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type upper struct{}

func (upper) Serve(_ context.Context, info Info, c Conn) error {
	for {
		b, err := c.Recv()
		if err != nil {
			return nil
		}
		out := append([]byte(nil), b...)
		for i := range out {
			if out[i] >= 'a' && out[i] <= 'z' {
				out[i] -= 32
			}
		}
		if info.XUID != 7 || info.ServiceID != 11 {
			out = []byte("wrong context")
		}
		if err := c.Send(out); err != nil {
			return err
		}
	}
}

func serve(t *testing.T, p *pki) string {
	creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{p.leaf(t, "spiffe://openpak/xb-tou", true)},
		ClientCAs: p.caPool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13})
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	s := grpc.NewServer(grpc.Creds(creds))
	Register(s, upper{})
	go s.Serve(lis)
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

func dial(t *testing.T, p *pki, addr, id string) *grpc.ClientConn {
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{p.leaf(t, id, false)}, RootCAs: p.caPool, ServerName: "localhost", MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return cc
}

func TestStreamRoundTripAndGatewayOnly(t *testing.T) {
	p := newPKI(t)
	addr := serve(t, p)

	got := make(chan []byte, 4)
	closed := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := Open(ctx, dial(t, p, addr, GatewayID), Info{PrincipalID: "p", XUID: 7, ServiceID: 11},
		func(b []byte) error { got <- b; return nil }, func() { close(closed) })
	if err != nil {
		t.Fatal(err)
	}
	st.Send([]byte("get /x"))
	if b := <-got; string(b) != "GET /X" {
		t.Fatalf("%q", b)
	}
	st.Close()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("onClose not called")
	}

	// A valid-CA client without the gateway identity is refused.
	if _, err := Open(ctx, dial(t, p, addr, "spiffe://openpak/other"), Info{XUID: 7, ServiceID: 11},
		func([]byte) error { return nil }, func() {}); err == nil {
		t.Fatal("non-gateway peer was served")
	}
	// A context without an XUID is refused.
	if _, err := Open(ctx, dial(t, p, addr, GatewayID), Info{ServiceID: 11},
		func([]byte) error { return nil }, func() {}); err == nil {
		t.Fatal("anonymous context was served")
	}
	_ = io.EOF
}

// slow answers after a pause that outlives the client's half-close; it checks
// its context the way a core call would.
type slow struct{ err chan error }

func (h slow) Serve(ctx context.Context, _ Info, c Conn) error {
	if _, err := c.Recv(); err != nil {
		return nil
	}
	time.Sleep(150 * time.Millisecond)
	h.err <- ctx.Err()
	return c.Send([]byte("reply"))
}

// The console's FIN right after its request (the gateway then closes the
// stream) must not cancel the handler or lose the reply.
func TestHalfCloseDoesNotCancelHandler(t *testing.T) {
	for name, closer := range map[string]func(*Stream){"closesend": (*Stream).CloseSend, "close": (*Stream).Close} {
		p := newPKI(t)
		h := slow{make(chan error, 1)}
		creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{p.leaf(t, "spiffe://openpak/xb-social", true)},
			ClientCAs: p.caPool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13})
		lis, _ := net.Listen("tcp", "127.0.0.1:0")
		s := grpc.NewServer(grpc.Creds(creds))
		Register(s, h)
		go s.Serve(lis)
		defer s.Stop()
		got := make(chan []byte, 2)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		st, err := Open(ctx, dial(t, p, lis.Addr().String(), GatewayID), Info{PrincipalID: "p", XUID: 7, ServiceID: 1},
			func(b []byte) error { got <- b; return nil }, func() {})
		if err != nil {
			t.Fatal(err)
		}
		st.Send([]byte("req"))
		closer(st)
		select {
		case b := <-got:
			if string(b) != "reply" {
				t.Fatalf("%s: %q", name, b)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: reply lost after half-close", name)
		}
		if err := <-h.err; err != nil {
			t.Fatalf("%s: handler context cancelled: %v", name, err)
		}
		cancel()
	}
}
