// SPDX-License-Identifier: AGPL-3.0-only
// Package adapter projects original Xbox identities from the console-neutral core.
package adapter

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	pb "openpak/xb-live/services/xb-account/internal/corepb"
)

const Namespace = "xbox"

var (
	ErrUnknown     = errors.New("identity unavailable")
	ErrDisabled    = errors.New("account disabled")
	ErrUnavailable = errors.New("account core unavailable")
)

type Identity struct {
	XUID        string `json:"xuid"`
	AccountID   string `json:"account_id"`
	DisplayName string `json:"display_name"`
}

type Core struct {
	links    pb.LinksClient
	identity pb.IdentityClient
	key      string
}

func NewCore(conn grpc.ClientConnInterface, key string) *Core {
	return &Core{pb.NewLinksClient(conn), pb.NewIdentityClient(conn), key}
}

// Resolve is an internal identity lookup, not proof of native sign-in. The caller
// must independently validate the native ticket and its possession proof.
// The adapter publishes the gamertag as the link public code when provisioning.
func (c *Core) Resolve(parent context.Context, gamertag string) (Identity, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.key)
	link, err := c.links.GetLinkByPublicCode(ctx, &pb.GetLinkByPublicCodeRequest{Namespace: Namespace, PublicCode: gamertag})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return Identity{}, ErrUnknown
		}
		return Identity{}, ErrUnavailable
	}
	if link.State != pb.LinkState_LINK_STATE_ACTIVE || link.AccountId == "" || !validXUID(link.SubjectId) {
		return Identity{}, ErrUnknown
	}
	account, err := c.identity.GetAccount(ctx, &pb.GetAccountRequest{AccountId: link.AccountId})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return Identity{}, ErrUnknown
		}
		return Identity{}, ErrUnavailable
	}
	if account.AccountId != link.AccountId {
		return Identity{}, ErrUnavailable
	}
	if account.Status != pb.AccountStatus_ACCOUNT_STATUS_ACTIVE {
		return Identity{}, ErrDisabled
	}
	// Re-read the link so an unlink during GetAccount cannot produce a stale success.
	current, err := c.links.GetLinkBySubject(ctx, &pb.GetLinkBySubjectRequest{Namespace: Namespace, SubjectId: link.SubjectId})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return Identity{}, ErrUnknown
		}
		return Identity{}, ErrUnavailable
	}
	if current.State != pb.LinkState_LINK_STATE_ACTIVE || current.LinkId != link.LinkId || current.AccountId != link.AccountId {
		return Identity{}, ErrUnknown
	}
	return Identity{link.SubjectId, account.AccountId, account.DisplayName}, nil
}

func validXUID(value string) bool {
	if len(value) != 16 || value != strings.ToLower(value) || value == "0000000000000000" {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

type Resolver interface {
	Resolve(context.Context, string) (Identity, error)
}

func Handler(resolver Resolver) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /internal/v1/resolve", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var request struct {
			Gamertag string `json:"gamertag"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !validGamertag(request.Gamertag) {
			http.Error(w, "invalid request", 400)
			return
		}
		identity, err := resolver.Resolve(r.Context(), request.Gamertag)
		switch {
		case errors.Is(err, ErrUnknown):
			http.Error(w, "identity unavailable", 404)
		case errors.Is(err, ErrDisabled):
			http.Error(w, "identity unavailable", 403)
		case err != nil:
			http.Error(w, "backend unavailable", 503)
		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(identity)
		}
	})
	return mux
}

func validGamertag(value string) bool {
	if len(value) < 1 || len(value) > 15 || strings.TrimSpace(value) != value {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == ' ') {
			return false
		}
	}
	return true
}
