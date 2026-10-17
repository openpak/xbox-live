// SPDX-License-Identifier: AGPL-3.0-only

// Package gateway is the Go port of Xombie's security-gateway (SG) transport.
// It terminates the native Xbox UDP protocol on port 3074 and holds only
// per-connection transport state. All feature state lives behind Backend.
package gateway

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

var (
	// ErrUnavailable is returned by a Backend (or the dispatcher when no backend
	// exists) to signal the native "service unavailable" outcome. The gateway
	// answers with a TCP reset; it never fabricates a success reply.
	ErrUnavailable = errors.New("service unavailable")
	// ErrUnauthenticated is returned by TicketVerifier and Directory implementations.
	ErrUnauthenticated = errors.New("ticket or principal rejected")
)

// ServiceMapping is one entry of the ticket's service-address list: the SG-internal
// TCP port a console may open and the numeric Xbox Live service behind it.
type ServiceMapping struct {
	ID   uint32
	Port uint16
}

// Identity is what a TicketVerifier extracts from a validated AP-REQ. The
// gateway never parses Kerberos itself; xb-auth's ticket format (internal/krb)
// plugs in by implementing TicketVerifier.
type Identity struct {
	XUID        uint64
	TitleID     uint32 // zero when the ticket carries no title
	SessionKey  [16]byte
	GatewayIP   netip.Addr // address the ticket was issued for
	Services    []ServiceMapping
	TicketStart time.Time
	TicketEnd   time.Time
	AuthTime    time.Time // authenticator ctime
	Checksum    []byte    // authenticator checksum over the init parameters (type -131)
	KeyID       string    // ticket-validation key rotation id that opened the ticket
	// BuildAPRep encodes the AP-REP whose subkey is the 20-byte digest the gateway computes.
	BuildAPRep func(subkey []byte) ([]byte, error)
}

// TicketVerifier decrypts and structurally validates the AP-REQ using the key
// shared with xb-auth (ticket validation key + rotation id). It must reject
// unknown rotation ids, malformed or mismatched principals, and unsupported
// versions. Time window, checksum, gateway address, replay and account checks
// are performed by the gateway so every verifier gets the same policy.
type TicketVerifier interface {
	VerifyAPReq(apReq []byte, now time.Time) (*Identity, error)
}

// Principal is the account directory's answer for a console user.
type Principal struct {
	PrincipalID   string
	CoreAccountID string
	Active        bool
}

// Directory resolves a XUID to an account principal (xb-account; mTLS client).
// The gateway fails closed if it errs or reports the principal inactive.
type Directory interface {
	ResolveUser(ctx context.Context, xuid uint64) (Principal, error)
}

// ConnContext is bound by the gateway from the validated ticket and directory
// answer. Backends must trust this and never read identity from client bytes.
type ConnContext struct {
	PrincipalID   string
	CoreAccountID string
	XUID          uint64
	TitleID       uint32
	ServiceID     uint32
	Generation    uint64 // unique per accepted SG connection
}

// Sink carries bytes from a backend to the console.
type Sink interface {
	Send(data []byte) error
	Close()
}

// Stream receives console bytes (in order) for one service connection.
type Stream interface {
	Receive(data []byte) error
	Close()
}

// HalfCloser is implemented by streams that can be told the console will send
// no more bytes while the backend may still answer.
type HalfCloser interface{ CloseSend() }

// Backend is a feature service (gRPC over mTLS in production). Open returning
// ErrUnavailable produces the native unavailable outcome.
type Backend interface {
	Open(ctx context.Context, cc ConnContext, sink Sink) (Stream, error)
}

// Checker is optionally implemented by dependencies to report health.
type Checker interface {
	Check(ctx context.Context) error
}
