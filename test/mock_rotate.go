// Copyright 2020, Square, Inc.

package test

import (
	"context"
)

type MockSecretSetter struct {
	InitFunc        func(context.Context, map[string]string) error
	HandlerFunc     func(context.Context, map[string]string) (map[string]string, error)
	RotateFunc      func(secret map[string]string) error
	CredentialsFunc func(secret map[string]string) (username, password string)
}

func (m MockSecretSetter) Init(ctx context.Context, event map[string]string) error {
	if m.InitFunc != nil {
		return m.InitFunc(ctx, event)
	}
	return nil
}

func (m MockSecretSetter) Handler(ctx context.Context, event map[string]string) (map[string]string, error) {
	if m.HandlerFunc != nil {
		return m.HandlerFunc(ctx, event)
	}
	return nil, nil
}

func (m MockSecretSetter) Rotate(secret map[string]string) error {
	if m.RotateFunc != nil {
		return m.RotateFunc(secret)
	}
	return nil
}

func (m MockSecretSetter) Credentials(secret map[string]string) (username, password string) {
	if m.CredentialsFunc != nil {
		return m.CredentialsFunc(secret)
	}
	return "", ""
}
