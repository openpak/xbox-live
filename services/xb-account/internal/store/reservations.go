// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Gamertag reservations back the console's native signup name check
// (service 5 reservename). A reservation is a short-lived hold on one alias for
// one core account (and the console it was asked from); it is not an identity:
// no user, XUID, link or core state exists until provisioning finalizes.
// Availability looks at the same state that makes a name unavailable for
// provisioning: committed aliases, provisions that already fixed a gamertag
// and have not failed, and other accounts' unexpired holds.

var (
	// ErrNameTaken: the alias belongs to a user, an in-flight provision or
	// another account's hold.
	ErrNameTaken = errors.New("store: gamertag unavailable")
	// ErrAccountHasUser: the account already owns its one primary Xbox user.
	ErrAccountHasUser = errors.New("store: account already has an xbox user")
)

// Reservation is one hold.
type Reservation struct {
	Gamertag, MachineID, CoreAccountID string
	Expires                            time.Time
}

// takenTx reports whether alias is unavailable to account. Callers hold a
// write transaction (or accept a racy read for advisory use).
func takenTx(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, lower, account string, now int64) (bool, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM gamertag_aliases WHERE alias_lower=?`, lower).Scan(&n); err != nil || n > 0 {
		return n > 0, err
	}
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM provisions WHERE lower(gamertag)=? AND expires>? AND state IN ('claimed','reserved','activated','coded')`,
		lower, now).Scan(&n); err != nil || n > 0 {
		return n > 0, err
	}
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM name_reservations WHERE alias_lower=? AND expires>? AND core_account_id<>?`,
		lower, now, account).Scan(&n)
	return n > 0, err
}

// NameAvailable is an advisory, non-holding check used to offer alternatives.
func (s *Store) NameAvailable(ctx context.Context, gamertag, account string) (bool, error) {
	taken, err := takenTx(ctx, s.db, strings.ToLower(gamertag), account, s.unix())
	return !taken, err
}

// ReserveName holds gamertag for account/machine for ttl. Any earlier hold of
// the same account or console is released. It returns ErrNameTaken if the alias
// is unavailable and ErrAccountHasUser if the account already has a user,
// unless allowOwner (a test-deployment switch) skips that account policy check.
func (s *Store) ReserveName(ctx context.Context, machineID, account, gamertag string, ttl time.Duration, allowOwner bool) (Reservation, error) {
	n := s.unix()
	lower := strings.ToLower(gamertag)
	res := Reservation{Gamertag: gamertag, MachineID: machineID, CoreAccountID: account, Expires: time.Unix(n, 0).Add(ttl)}
	err := s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `DELETE FROM name_reservations WHERE expires<=?`, n); err != nil {
			return err
		}
		var c int
		if err := t.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE core_account_id=? AND status IN ('active','banned')`, account).Scan(&c); err != nil {
			return err
		}
		if c > 0 && !allowOwner {
			return ErrAccountHasUser
		}
		taken, err := takenTx(ctx, t, lower, account, n)
		if err != nil {
			return err
		}
		if taken {
			return ErrNameTaken
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM name_reservations WHERE core_account_id=? OR machine_id=?`, account, machineID); err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `INSERT INTO name_reservations(alias_lower,gamertag,machine_id,core_account_id,expires,created) VALUES(?,?,?,?,?,?)`,
			lower, gamertag, machineID, account, res.Expires.Unix(), n)
		if isUnique(err) {
			return ErrNameTaken
		}
		return err
	})
	return res, err
}

// GetReservation returns the unexpired hold of an account.
func (s *Store) GetReservation(ctx context.Context, account string) (Reservation, error) {
	var r Reservation
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT gamertag,machine_id,core_account_id,expires FROM name_reservations WHERE core_account_id=? AND expires>?`,
		account, s.unix()).Scan(&r.Gamertag, &r.MachineID, &r.CoreAccountID, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return Reservation{}, ErrNotFound
	}
	r.Expires = time.Unix(exp, 0)
	return r, err
}

// ReleaseReservation drops the account's hold (idempotent).
func (s *Store) ReleaseReservation(ctx context.Context, account string) error {
	return s.tx(ctx, func(t *sql.Tx) error {
		_, err := t.ExecContext(ctx, `DELETE FROM name_reservations WHERE core_account_id=?`, account)
		return err
	})
}
