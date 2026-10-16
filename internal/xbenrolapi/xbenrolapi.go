// SPDX-License-Identifier: AGPL-3.0-only

// Package xbenrolapi is the contract between xb-enroll (the thin public
// service) and xb-account (which owns all enrolment state): JSON types, error
// codes, input validation shared by both sides, and the mTLS client.
package xbenrolapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"openpak/xb-live/internal/xbaccountapi"
)

// Status values of an enrolment as seen by the console.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusExpired  = "expired" // also: failed, rolled back, or replaced; start over
)

// Error codes (the "error" member of a JSON error body).
const (
	CodeInvalidRequest = "invalid_request"
	CodeMachineActive  = "machine_already_enrolled"
	CodeRateLimited    = "rate_limited"
	CodeNotFound       = "not_found" // unknown poll token, or pairing code unknown/expired/used (indistinguishable)
	CodeNotEligible    = "account_not_eligible"
	CodeConflict       = "conflict" // account already has an Xbox link, or the device is bound elsewhere
	CodeBusy           = "busy"
	CodeUnavailable    = "unavailable"
)

const (
	MaxClientInfo = 64
	MaxBody       = 2048
	MaxTokenLen   = 128
)

// EnrolRequest registers a pending enrolment (xb-enroll -> xb-account).
type EnrolRequest struct {
	MachineID  string `json:"machine_id"`  // 16 lowercase hex (xbaccountapi.MachineID)
	MachineKey string `json:"machine_key"` // 32 hex characters, the 16-byte machine key
	ClientInfo string `json:"client_info,omitempty"`
}

type EnrolResponse struct {
	PairingCode string `json:"pairing_code"` // 8 characters, xbcodes alphabet
	PollToken   string `json:"poll_token"`
	ExpiresUnix int64  `json:"expires_unix"`
}

type PollRequest struct {
	PollToken string `json:"poll_token"`
}

type PollResponse struct {
	Status      string `json:"status"`
	ExpiresUnix int64  `json:"expires_unix"`
}

// ErrorBody is every error response.
type ErrorBody struct {
	Error string `json:"error"`
}

// ParseMachineID accepts the 16-hex machine ID or the 12-digit decimal serial
// printed on the console and returns the machine ID.
func ParseMachineID(s string) (string, bool) {
	if len(s) == 12 && strings.Trim(s, "0123456789") == "" {
		var n uint64
		for _, c := range s {
			n = n*10 + uint64(c-'0')
		}
		return xbaccountapi.MachineID(n)
	}
	s = strings.ToLower(s)
	return s, xbaccountapi.ValidMachineID(s)
}

// ParseMachineKey decodes a 32-hex-character machine key. All-zero and
// all-0xff blocks (an unread or erased EEPROM) are rejected.
func ParseMachineKey(s string) ([]byte, bool) {
	if len(s) != 32 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, false
	}
	zero, ones := true, true
	for _, c := range b {
		zero = zero && c == 0
		ones = ones && c == 0xff
	}
	if zero || ones {
		return nil, false
	}
	return b, true
}

// CleanClientInfo returns s if it is short printable ASCII, else "", false.
func CleanClientInfo(s string) (string, bool) {
	if len(s) > MaxClientInfo {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return "", false
		}
	}
	return s, true
}

// Error is returned by Client for a non-2xx answer.
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return "xbenrolapi: " + e.Code }

// ErrUnavailable covers transport failures.
var ErrUnavailable = errors.New("xbenrolapi: xb-account unreachable")

// Client calls xb-account's xb-enroll routes. HTTP must carry the caller's
// mTLS identity (spiffe://openpak/xb-enroll).
type Client struct {
	Base string
	HTTP *http.Client
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return ErrUnavailable
	}
	if resp.StatusCode/100 != 2 {
		var eb ErrorBody
		if json.Unmarshal(data, &eb) != nil || eb.Error == "" {
			eb.Error = CodeUnavailable
		}
		return &Error{resp.StatusCode, eb.Error}
	}
	if json.Unmarshal(data, out) != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) Enrol(ctx context.Context, r EnrolRequest) (EnrolResponse, error) {
	var out EnrolResponse
	err := c.post(ctx, "/internal/v1/enrolments", r, &out)
	return out, err
}

func (c *Client) Poll(ctx context.Context, token string) (PollResponse, error) {
	var out PollResponse
	err := c.post(ctx, "/internal/v1/enrolments/poll", PollRequest{token}, &out)
	return out, err
}
