package rotate_test

import (
	"strings"
	"testing"

	rotate "github.com/square/password-rotation-lambda/v2"
)

func TestRandomPassword_Default(t *testing.T) {
	var rp rotate.RandomPassword

	secret := map[string]string{
		"username": "test-user",
		"password": "original-password",
	}

	err := rp.Rotate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret["password"]) != rotate.DEFAULT_PASSWORD_LENGTH {
		t.Fatalf("expected the default RandomPassword to generate passwords with %d characters, got %d characters", rotate.DEFAULT_PASSWORD_LENGTH, len(secret["password"]))
	}
}

func TestRandomPassword_Custom(t *testing.T) {
	rp := rotate.RandomPassword{
		PasswordLength: 1,
	}

	secret := map[string]string{
		"username": "test-user",
		"password": "original-password",
	}

	err := rp.Rotate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret["password"]) != rp.PasswordLength {
		t.Fatalf("expected the custom RandomPassword to generate passwords with %d characters, got %d characters", rp.PasswordLength, len(secret["password"]))
	}

	rp = rotate.RandomPassword{
		ValidCharset: []rune("X"),
	}

	secret = map[string]string{
		"username": "test-user",
		"password": "original-password",
	}

	err = rp.Rotate(secret)
	if err != nil {
		t.Fatal(err)
	}
	if secret["password"] != strings.Repeat("X", rotate.DEFAULT_PASSWORD_LENGTH) {
		t.Fatalf("expected to generate password '%s' from single character charset, got '%s'", strings.Repeat("X", rotate.DEFAULT_PASSWORD_LENGTH), secret["password"])
	}
}
