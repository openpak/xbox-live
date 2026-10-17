// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"errors"
	"openpak/xb-live/internal/xbaccountapi"
	"strings"
)

// Automatic identities (internal/autoid): every OpenPak account has an Xbox
// identity (xuid + gamertag) without a console step. Such an identity has a
// users row and a gamertag alias but no device and no credentials, and is
// listed in auto_identities so a real enrolment can retire and replace it.

// AutoIdentity returns the automatic identity of the account, if any.
func (s *Store) AutoIdentity(ctx context.Context, account string) (User, bool, error) {
	var u User
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT u.xuid,u.core_account_id,u.gamertag,u.link_id,u.status FROM auto_identities a JOIN users u ON u.xuid=a.xuid WHERE a.core_account_id=?`, account).
		Scan(&u.XUID, &u.CoreAccountID, &u.Gamertag, &u.LinkID, &st)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	u.Status = statusOf(st)
	return u, err == nil, err
}

// ActiveUserOf returns the account's active or banned primary user row.
func (s *Store) ActiveUserOf(ctx context.Context, account string) (User, bool, error) {
	var u User
	var st string
	err := s.db.QueryRowContext(ctx, `SELECT xuid,core_account_id,gamertag,link_id,status FROM users WHERE core_account_id=? AND status IN ('active','banned')`, account).
		Scan(&u.XUID, &u.CoreAccountID, &u.Gamertag, &u.LinkID, &st)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	u.Status = statusOf(st)
	return u, err == nil, err
}

// CommitAuto creates the user, the gamertag alias and the auto marker atomically.
// ErrConflict: the account already has a primary user, or the gamertag/xuid is taken.
func (s *Store) CommitAuto(ctx context.Context, u User) error {
	n := s.unix()
	return s.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `INSERT INTO users(xuid,core_account_id,gamertag,link_id,status,created,updated) VALUES(?,?,?,?,'active',?,?)`,
			u.XUID, u.CoreAccountID, u.Gamertag, u.LinkID, n, n); err != nil {
			return conflict(err)
		}
		if _, err := t.ExecContext(ctx, `INSERT INTO gamertag_aliases(alias_lower,xuid,created) VALUES(?,?,?)`, strings.ToLower(u.Gamertag), u.XUID, n); err != nil {
			return conflict(err)
		}
		_, err := t.ExecContext(ctx, `INSERT INTO auto_identities(core_account_id,xuid,created) VALUES(?,?,?)`, u.CoreAccountID, u.XUID, n)
		return conflict(err)
	})
}

// RetireAuto ends the account's automatic identity (a real enrolment replaces
// it): the user row becomes unlinked, its alias is freed, the marker is removed.
func (s *Store) RetireAuto(ctx context.Context, account string) error {
	n := s.unix()
	return s.tx(ctx, func(t *sql.Tx) error {
		var xuid string
		err := t.QueryRowContext(ctx, `SELECT xuid FROM auto_identities WHERE core_account_id=?`, account).Scan(&xuid)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `UPDATE users SET status='unlinked',updated=? WHERE xuid=?`, n, xuid); err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM gamertag_aliases WHERE xuid=?`, xuid); err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `DELETE FROM auto_identities WHERE core_account_id=?`, account)
		return err
	})
}

func statusOf(s string) xbaccountapi.Status { return xbaccountapi.Status(s) }
