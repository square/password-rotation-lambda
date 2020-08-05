// Copyright 2020, Square, Inc.

package test

import (
	"context"

	"github.com/square/password-rotation-lambda/db"
)

type MockPasswordSetter struct {
	InitFunc           func(context.Context, map[string]string) error
	SetPasswordFunc    func(ctx context.Context, creds db.NewPassword) error
	VerifyPasswordFunc func(ctx context.Context, creds db.NewPassword) error
	RollBackFunc       func(ctx context.Context, creds db.NewPassword) error
}

func (m MockPasswordSetter) Init(ctx context.Context, s map[string]string) error {
	if m.InitFunc != nil {
		return m.InitFunc(ctx, s)
	}
	return nil
}

func (m MockPasswordSetter) SetPassword(ctx context.Context, creds db.NewPassword) error {
	if m.SetPasswordFunc != nil {
		return m.SetPasswordFunc(ctx, creds)
	}
	return nil
}

func (m MockPasswordSetter) VerifyPassword(ctx context.Context, creds db.NewPassword) error {
	if m.VerifyPasswordFunc != nil {
		return m.VerifyPasswordFunc(ctx, creds)
	}
	return nil
}

func (m MockPasswordSetter) RollBack(ctx context.Context, creds db.NewPassword) error {
	if m.RollBackFunc != nil {
		return m.RollBackFunc(ctx, creds)
	}
	return nil
}
