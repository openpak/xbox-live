// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// MTLSFiles locate the gateway's client identity and the CA that signs feature
// backends. Paths come from the environment; the files are mounted read-only
// and never baked into an image.
type MTLSFiles struct {
	Cert, Key, CA string
	ServerName    string
}

// DialOption builds a TLS 1.3 mutual-TLS gRPC dial option.
func (f MTLSFiles) DialOption() (grpc.DialOption, error) {
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(f.CA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("no CA certificates in bundle")
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: f.ServerName, MinVersion: tls.VersionTLS13,
	})), nil
}

// GRPCBackend is the client stub for a separate feature service. The feature
// RPC contract (stream open with ConnContext, bidirectional bytes) is not yet
// defined, so Open reports ErrUnavailable: the console sees a native
// "unavailable", never an invented success. Replace Open once the service
// protocol exists; the dial, mTLS and health plumbing are already real.
type GRPCBackend struct {
	Target string
	conn   *grpc.ClientConn
}

// NewGRPCBackend creates a lazily connecting client (no network I/O here).
func NewGRPCBackend(target string, opt grpc.DialOption) (*GRPCBackend, error) {
	c, err := grpc.NewClient(target, opt)
	if err != nil {
		return nil, err
	}
	return &GRPCBackend{Target: target, conn: c}, nil
}

func (b *GRPCBackend) Open(context.Context, ConnContext, Sink) (Stream, error) {
	return nil, ErrUnavailable
}

// Check reports whether the channel is currently connected (idle counts as reachable).
func (b *GRPCBackend) Check(ctx context.Context) error {
	switch st := b.conn.GetState().String(); st {
	case "TRANSIENT_FAILURE", "SHUTDOWN":
		return errors.New("backend channel " + st)
	}
	return nil
}

func (b *GRPCBackend) Close() error { return b.conn.Close() }
