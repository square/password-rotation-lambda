// Copyright 2020, Square, Inc.

package db

import (
	"context"
)

// Credentials represents one set of database credentials.
type Credentials struct {
	Username string
	Hostname string
	Password string
}

// NewPassword represents current and new credentials. This is the primary
// data structure used throughout the code to rotate the database password
// from the current to the new credentials.
type NewPassword struct {
	Current Credentials
	New     Credentials
}

// PasswordSetter changes and verifies database passwords. A database-specific
// implementation, like mysql.PasswordSetter, handles the low-level details.
// PasswordSetter is used by rotate.Rotator to abstract away the database details.
type PasswordSetter interface {
	// Init is always called first and potentially called multiple times.
	// The PasswordSetter should prepare itself, e.g. find all database instances.
	// The sercets values are given to provide any user-specific data which
	// Init can use to refine its preparation.
	Init(ctx context.Context, secret map[string]string) error

	// SetPassword changes the password from the current to the new credentials.
	// The database-specific implementation must track which databases were successfully
	// changed or not. On failure, the caller might call RollBack to reverse the
	// successfully changed databases, i.e. restore all database to the original
	// credentials.
	SetPassword(ctx context.Context, creds NewPassword) error

	// VerifyPassword verifies the new credentials.
	VerifyPassword(ctx context.Context, creds NewPassword) error

	// RollBack reverses SetPassword by changing the password from the new to
	// the current (original) credentials. The database-specific implementation
	// must track and roll back only the databases which were successfully changed
	// by SetPassword.
	RollBack(ctx context.Context, creds NewPassword) error
}
