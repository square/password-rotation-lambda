// Copyright 2020, Square, Inc.

package rotate

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// SecretSetter manages the user-specific secret value. Rotator has only one
// requirement for the secret: it is a JSON string with key-value pairs.
// When Rotator gets the secret, it unmarshals the secret string as JSON into
// the map[string]string and passes it to the interface methods.
//
// The secret value is user-defined. A suggested minimum value is:
//
//   {
//     "username": "foo",
//     "password": "bar"
//   }
//
// Using that value as an exmaple, the Rotate method would change "password"
// to rotate the password, and the Credentials method would return "foo", "bar".
//
// RandomPassword is used if no SecretSetter is specified in the Config passed
// to NewRotator.
type SecretSetter interface {
	// Init is called before every Secrets Manager rotation step. Any user-specific
	// initialization should be done.
	Init(ctx context.Context, secret map[string]string) error

	// Handler is called if the event is not from Secrets Manager (user-invoked
	// password rotation). The event is user-defined data. After calling this method,
	// the Lambda function is done and no other methods are called.
	Handler(ctx context.Context, event map[string]string) error

	// Rotate changes the password in the secret. The method is expected to modify
	// the secret map. The caller (Rotator) passes the same map to Credentials to
	// return the username and password to set on the databases.
	Rotate(secret map[string]string) error

	// Credentials returns the username and password to set on the databases.
	Credentials(secret map[string]string) (username, password string)
}

const (
	DEFAULT_PASSWORD_LENGTH = 20 // password character length for RandomPassword
)

// RandomPassword is the default SecretSetter used by Rotator is none is
// specified in the Config. It requires the secret value to have two JSON fields:
// username and password. Other fields are ignored. It sets a random password
// DEFAULT_PASSWORD_LENGTH characters long using these characters:
//
//   ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-
//
// RandomPassword does not support Handler (user-invoked password rotation),
// it only supports rotation by Secrets Manager.
type RandomPassword struct{}

var _ RandomPassword = RandomPassword{}

func (s RandomPassword) Init(context.Context, map[string]string) error {
	return nil // nothing we need to do
}

func (s RandomPassword) Handler(context.Context, map[string]string) error {
	return fmt.Errorf("RandomPassword does not support user-invoked password rotation")
}

var chars = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-")

func (s RandomPassword) Rotate(secret map[string]string) error {
	// Make a 20 char random password
	rand.Seed(time.Now().UnixNano())
	newPassword := make([]rune, 20)
	for i := 0; i < 20; i++ {
		newPassword[i] = chars[rand.Intn(len(chars))]
	}
	secret["password"] = string(newPassword)
	return nil
}

func (s RandomPassword) Credentials(secret map[string]string) (username, password string) {
	// Our secret is really simple, just these fields:
	return secret["username"], secret["password"]
}
