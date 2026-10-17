// SPDX-License-Identifier: AGPL-3.0-only

// Package xbfeature is the gateway-to-feature-service stream contract: one
// bidirectional gRPC stream per console TCP connection, carrying raw bytes.
// Messages are google.protobuf.BytesValue so no code generation is needed.
//
//	client -> server: frame 1 = JSON Info (identity bound by the gateway from
//	                  the validated ticket; never from console bytes),
//	                  later frames = console bytes in order
//	server -> client: frame 1 = empty ack (the service accepted the stream),
//	                  later frames = bytes for the console
//
// Closing either side ends the console connection. A service that is down or
// refuses the stream makes the gateway answer with the native "unavailable".
package xbfeature

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	serviceName = "openpak.xb.v1.Feature"
	method      = "/" + serviceName + "/Connect"
	// GatewayID is the SPIFFE URI the gateway's client certificate must carry.
	GatewayID = "spiffe://openpak/xb-gateway"
	maxFrame  = 64 << 10
)

// Info is the connection context the gateway binds.
type Info struct {
	PrincipalID   string `json:"principal_id"`
	CoreAccountID string `json:"core_account_id"`
	XUID          uint64 `json:"xuid"`
	TitleID       uint32 `json:"title_id"`
	ServiceID     uint32 `json:"service_id"`
	Generation    uint64 `json:"generation"`
}

// Conn is the service side of one console connection.
type Conn interface {
	// Recv returns the next chunk of console bytes; io.EOF when the console closed.
	Recv() ([]byte, error)
	Send([]byte) error
}

// Handler serves one console connection. Returning ends it.
type Handler interface {
	Serve(ctx context.Context, info Info, c Conn) error
}

// ---- server ----

type server struct{ h Handler }

// Register installs h on s. Callers must configure mutual TLS and call
// PeerIsGateway through the interceptor this package installs.
func Register(s *grpc.Server, h Handler) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName: "Connect", ClientStreams: true, ServerStreams: true,
			Handler: func(_ any, st grpc.ServerStream) error { return (&server{h}).connect(st) },
		}},
	}, &server{h})
}

// PeerIsGateway reports whether the verified client certificate carries GatewayID.
func PeerIsGateway(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return false
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	return ok && isGateway(ti.State)
}

func isGateway(s tls.ConnectionState) bool {
	if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
		return false
	}
	for _, u := range s.PeerCertificates[0].URIs {
		if u.String() == GatewayID {
			return true
		}
	}
	return false
}

type srvConn struct{ st grpc.ServerStream }

func (c srvConn) Recv() ([]byte, error) {
	var m wrapperspb.BytesValue
	if err := c.st.RecvMsg(&m); err != nil {
		if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
			return nil, io.EOF
		}
		return nil, err
	}
	return m.Value, nil
}
func (c srvConn) Send(b []byte) error {
	if len(b) > maxFrame {
		return errors.New("xbfeature: frame too large")
	}
	return c.st.SendMsg(&wrapperspb.BytesValue{Value: b})
}

func (s *server) connect(st grpc.ServerStream) error {
	if !PeerIsGateway(st.Context()) {
		return status.Error(codes.PermissionDenied, "gateway identity required")
	}
	c := srvConn{st}
	raw, err := c.Recv()
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return status.Error(codes.InvalidArgument, "missing connection context")
	}
	var info Info
	if err := json.Unmarshal(raw, &info); err != nil || info.XUID == 0 {
		return status.Error(codes.InvalidArgument, "bad connection context")
	}
	if err := c.Send(nil); err != nil { // ack
		return err
	}
	// The console half-closing its TCP side right after a request is normal
	// (HTTP/1.0), and the gateway may tear its side down at once. That must not
	// cancel work in flight: the handler's context ends only when the handler
	// returns or the gateway is really gone (a send fails). It is detached from
	// the stream's cancellation; callers bound each backend call themselves.
	ctx, cancel := context.WithCancel(context.WithoutCancel(st.Context()))
	defer cancel()
	return s.h.Serve(ctx, info, &cancelOnSendFail{c, cancel})
}

type cancelOnSendFail struct {
	Conn
	cancel context.CancelFunc
}

func (c *cancelOnSendFail) Send(b []byte) error {
	err := c.Conn.Send(b)
	if err != nil {
		c.cancel()
	}
	return err
}

// ---- client (gateway side) ----

// Stream is an open console connection on the client side.
type Stream struct {
	cs     grpc.ClientStream
	cancel context.CancelFunc
	mu     sync.Mutex
	// finished closes when the reader has ended (stream over).
	finished chan struct{}
}

// Open starts a stream and waits for the service's ack within ctx. onData and
// onClose run on a reader goroutine; onClose runs once.
func Open(ctx context.Context, cc *grpc.ClientConn, info Info, onData func([]byte) error, onClose func()) (*Stream, error) {
	sctx, cancel := context.WithCancel(context.Background())
	cs, err := cc.NewStream(sctx, &grpc.StreamDesc{StreamName: "Connect", ClientStreams: true, ServerStreams: true}, method)
	if err != nil {
		cancel()
		return nil, err
	}
	s := &Stream{cs: cs, cancel: cancel, finished: make(chan struct{})}
	raw, _ := json.Marshal(info)
	if err := s.send(raw); err != nil {
		cancel()
		return nil, err
	}
	acked := make(chan error, 1)
	go func() {
		var m wrapperspb.BytesValue
		if err := cs.RecvMsg(&m); err != nil {
			acked <- err
			return
		}
		acked <- nil
		defer onClose()
		defer close(s.finished)
		for {
			var m wrapperspb.BytesValue
			if err := cs.RecvMsg(&m); err != nil {
				return
			}
			if len(m.Value) > 0 && onData(m.Value) != nil {
				return
			}
		}
	}()
	select {
	case err := <-acked:
		if err != nil {
			cancel()
			return nil, err
		}
		return s, nil
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

func (s *Stream) send(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cs.SendMsg(&wrapperspb.BytesValue{Value: b})
}

// Send forwards console bytes.
func (s *Stream) Send(b []byte) error { return s.send(b) }

// CloseSend half-closes: no more console bytes, the service may still answer.
func (s *Stream) CloseSend() {
	s.mu.Lock()
	s.cs.CloseSend()
	s.mu.Unlock()
}

// Close ends the connection gracefully: it half-closes and gives the service
// up to CloseGrace to finish and send its reply before the stream is cancelled
// (a request followed at once by the console's FIN must still be answered).
func (s *Stream) Close() {
	s.CloseSend()
	t := time.AfterFunc(CloseGrace, s.cancel)
	go func() {
		<-s.finished
		t.Stop()
		s.cancel()
	}()
}

// Abort cancels the stream immediately, dropping any reply.
func (s *Stream) Abort() { s.CloseSend(); s.cancel() }

// CloseGrace bounds how long Close waits for the service to finish.
var CloseGrace = 10 * time.Second
