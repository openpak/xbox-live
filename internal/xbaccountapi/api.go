// SPDX-License-Identifier: AGPL-3.0-only

// Package xbaccountapi is the contract between xb-account and its consumers
// (xb-auth, xb-gateway). xb-account implements Resolver and Revocations;
// consumers use Client over mutual TLS. Resolution proves that a principal is
// known and permitted; it does NOT prove possession of a native credential
// (Kerberos or otherwise). Consumers must validate tickets separately.
package xbaccountapi

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Status is the admission status of a principal. Only StatusActive admits.
type Status string

const (
	StatusActive   Status = "active"
	StatusBanned   Status = "banned"
	StatusUnlinked Status = "unlinked"
	StatusRevoked  Status = "revoked" // credential revoked (devices)
	StatusDeleted  Status = "deleted"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusBanned, StatusUnlinked, StatusRevoked, StatusDeleted:
		return true
	}
	return false
}

type Kind string

const (
	KindUser   Kind = "user"   // identified by XUID (16 lowercase hex)
	KindDevice Kind = "device" // identified by machine ID (16 lowercase hex)
)

// Principal is an admitted identity. PrincipalID is the XUID for users and the
// machine ID for devices; the two spaces are distinct and never conflated.
type Principal struct {
	Kind          Kind   `json:"kind"`
	PrincipalID   string `json:"principal_id"`
	CoreAccountID string `json:"core_account_id"`
	Status        Status `json:"status"`
}

var (
	// ErrNotFound: no such principal.
	ErrNotFound = errors.New("xbaccountapi: principal not found")
	// ErrUnavailable: the answer could not be determined; callers must deny.
	ErrUnavailable = errors.New("xbaccountapi: resolver unavailable")
	// ErrInvalid: malformed identifier.
	ErrInvalid = errors.New("xbaccountapi: invalid identifier")
	// ErrDenied is matched with errors.Is for any DeniedError.
	ErrDenied = errors.New("xbaccountapi: principal denied")
)

// DeniedError is returned for a known principal that must not be admitted
// (banned, unlinked, revoked, deleted). Principal carries the reason.
type DeniedError struct{ Principal Principal }

func (e *DeniedError) Error() string {
	return fmt.Sprintf("xbaccountapi: %s denied: %s", e.Principal.Kind, e.Principal.Status)
}
func (e *DeniedError) Is(target error) bool { return target == ErrDenied }

// Resolver maps native identifiers to principals. A nil error means the
// principal is active; every other outcome is a denial, including
// ErrUnavailable. There is no positive cache contract: implementations
// re-check authoritative state.
type Resolver interface {
	ResolveUser(ctx context.Context, xuid string) (Principal, error)
	ResolveDevice(ctx context.Context, machineID string) (Principal, error)
	// ResolveGamertag maps a native gamertag (case-insensitive) to its user
	// principal, with the same admission rules as ResolveUser. The returned
	// PrincipalID is the XUID. Like every method here it is not proof of
	// credential possession.
	ResolveGamertag(ctx context.Context, gamertag string) (Principal, error)
}

// ValidGamertag reports whether v has the shape of a native gamertag:
// 1-15 ASCII letters, digits or inner spaces.
func ValidGamertag(v string) bool {
	if len(v) < 1 || len(v) > 15 || v[0] == ' ' || v[len(v)-1] == ' ' {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ') {
			return false
		}
	}
	return true
}

// Scope of a revocation.
type Scope string

const (
	ScopeUser    Scope = "user"    // PrincipalID = XUID; drop that user's sessions
	ScopeDevice  Scope = "device"  // PrincipalID = machine ID
	ScopeAccount Scope = "account" // every session of CoreAccountID
)

// Revocation is one durable entry of the revocation stream. Seq is strictly
// increasing; EventID is the core event that caused it and is unique.
type Revocation struct {
	Seq           uint64 `json:"seq"`
	EventID       string `json:"event_id"`
	Scope         Scope  `json:"scope"`
	PrincipalID   string `json:"principal_id,omitempty"`
	CoreAccountID string `json:"core_account_id"`
	Reason        Status `json:"reason"`
	CreatedUnix   int64  `json:"created_unix"`
}

// Revocations is the cursor-based stream. Consumers persist the highest Seq
// they applied and call Poll(after). Delivery is at-least-once in order;
// applying a revocation twice must be harmless. Poll waits up to wait for
// new entries when none are available (wait 0 returns immediately).
type Revocations interface {
	Poll(ctx context.Context, after uint64, limit int, wait time.Duration) ([]Revocation, error)
}

// ValidID reports whether id is a 16-character lowercase hex identifier that
// is not all zero (XUIDs and machine IDs share this shape).
func ValidID(id string) bool {
	if len(id) != 16 || id == "0000000000000000" {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
