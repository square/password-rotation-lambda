// Copyright 2020, Square, Inc.

package test

import (
	"context"

	"github.com/square/password-rotation-lambda/db"
)

type MockMySQLPasswordClient struct {
	SetPasswordFunc    func(ctx context.Context, creds db.NewPassword) error
	VerifyPasswordFunc func(ctx context.Context, creds db.NewPassword) error
}

func (m MockMySQLPasswordClient) SetPassword(ctx context.Context, creds db.NewPassword) error {
	if m.SetPasswordFunc != nil {
		return m.SetPasswordFunc(ctx, creds)
	}
	return nil
}

func (m MockMySQLPasswordClient) VerifyPassword(ctx context.Context, creds db.NewPassword) error {
	if m.VerifyPasswordFunc != nil {
		return m.VerifyPasswordFunc(ctx, creds)
	}
	return nil
}
