// Copyright 2020, Square, Inc.

package rotate_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/go-test/deep"

	rotate "github.com/square/password-rotation-lambda/v2"
	"github.com/square/password-rotation-lambda/v2/db"
	"github.com/square/password-rotation-lambda/v2/test"
)

var (
	secretString0 = `{"password":"p0","username":"foo","v":"0"}`
	secretString1 = `{"password":"p1","username":"foo","v":"1"}`
	secretString2 = `{"password":"p2","username":"foo","v":"2"}`
	now           = time.Now()
)

func init() {
	rotate.Debug = true
	rotate.DebugSecret = true
}

func TestStepCreateSecretNew(t *testing.T) {
	// Test that the "createSecret" step gets the current secret, sets a new one,
	// and puts it back as pending. This is the first step in the four-step process.
	// This also tests when there's no pending secret, i.e. first call. The test
	// after this one tests createSecret on retry when there's already a pending secret.
	gotGetStages := []string{}
	var gotPutInput *secretsmanager.PutSecretValueInput
	var updateSecretVersionCalled bool

	// Create mock Secrets Manager client (mock AWS API calls) and SecretSetter
	// (mock user-provided one)
	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			gotGetStages = append(gotGetStages, *input.VersionStage)
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return nil, awserr.New(
					secretsmanager.ErrCodeResourceNotFoundException,
					"not found",
					nil,
				)
			default:
				return nil, nil
			}

		},
		PutSecretValueFunc: func(input *secretsmanager.PutSecretValueInput) (*secretsmanager.PutSecretValueOutput, error) {
			gotPutInput = input
			return &secretsmanager.PutSecretValueOutput{
				ARN:           aws.String("arn"),
				Name:          aws.String("sercetName"),
				VersionId:     aws.String("v2"),
				VersionStages: []*string{aws.String(rotate.AWSPENDING)},
			}, nil
		},
		UpdateSecretVersionStageFunc: func(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
			updateSecretVersionCalled = true
			return nil, nil
		},
	}

	ss := test.MockSecretSetter{
		RotateFunc: func(secret map[string]string) error {
			secret["password"] = "p2" // matches secretString2
			secret["v"] = "2"         // matches secretString2
			return nil
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   ss,
		PasswordSetter: test.MockPasswordSetter{},
	})

	// Simulate createSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "createSecret",
	}
	_, err := r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}

	// The code should get the current secret then the pending because the current
	// doesn't have the pending label
	expectGetStages := []string{rotate.AWSCURRENT, rotate.AWSPENDING}
	if diff := deep.Equal(gotGetStages, expectGetStages); diff != nil {
		t.Error(diff)
	}

	// Then it should set the new secret (secretString2) as pending
	expectPutInput := &secretsmanager.PutSecretValueInput{
		ClientRequestToken: aws.String("abc"),
		SecretId:           aws.String("def"),
		SecretString:       aws.String(secretString2),
		VersionStages:      []*string{aws.String(rotate.AWSPENDING)},
	}
	if diff := deep.Equal(gotPutInput, expectPutInput); diff != nil {
		t.Error(diff)
	}

	// The code should not call UpdateSecretVersionStage. That doesn't happen
	// until the last step.
	if updateSecretVersionCalled {
		t.Errorf("UpdateSecretVersionStage called, expected no call by CreateSecret")
	}
}

func TestStepCreateSecretRetry(t *testing.T) {
	// Test that the "createSecret" step uses the pending secret from a previous call,
	// i.e. that the step can be retried. This only work if clientRequestToken = the
	// pending secret version id. We know it works when gotPutInput == nil, i.e. it
	// does _not_ put a new pending secret because it already exists.
	gotGetStages := []string{}
	var gotPutInput *secretsmanager.PutSecretValueInput

	// Create mock Secrets Manager client (mock AWS API calls) and SecretSetter
	// (mock user-provided one)
	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			gotGetStages = append(gotGetStages, *input.VersionStage)
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("abc"), // must match ClientRequestToken below
					VersionStages: []*string{aws.String(rotate.AWSPENDING)},
					CreatedDate:   &now,
				}, nil
			default:
				return nil, nil
			}

		},
		PutSecretValueFunc: func(input *secretsmanager.PutSecretValueInput) (*secretsmanager.PutSecretValueOutput, error) {
			gotPutInput = input
			return &secretsmanager.PutSecretValueOutput{
				ARN:           aws.String("arn"),
				Name:          aws.String("sercetName"),
				VersionId:     aws.String("v2"),
				VersionStages: []*string{aws.String(rotate.AWSPENDING)},
			}, nil
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   test.MockSecretSetter{},
		PasswordSetter: test.MockPasswordSetter{},
	})

	// Simulate createSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "createSecret",
	}
	_, err := r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}

	// The code should get the current secret then the pending because the current
	// doesn't have the pending label
	expectGetStages := []string{rotate.AWSCURRENT, rotate.AWSPENDING}
	if diff := deep.Equal(gotGetStages, expectGetStages); diff != nil {
		t.Error(diff)
	}

	// No new pending secret is put because this is a retry, i.e. pending secret
	// already exists
	if gotPutInput != nil {
		t.Errorf("new pending secret put, expected nil: %+v", *gotPutInput)
	}
}

func TestStepSetSecret(t *testing.T) {
	// Test that the "setSecret" step gets both secrets (current and pending),
	// gets the db creds from pending, and sets them via PasswordSetter. This is
	// the second step in the four-step process.
	var updateSecretVersionCalled bool
	var nCallsToGetSecretValue int

	// Create mock Secrets Manager client (mock AWS API calls) and SecretSetter
	// (mock user-provided one)
	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			nCallsToGetSecretValue++
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v2"),
					VersionStages: []*string{aws.String(rotate.AWSPENDING)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPREVIOUS:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v0"),
					VersionStages: []*string{aws.String(rotate.AWSPREVIOUS)},
					CreatedDate:   &now,
				}, nil
			default:
				return nil, nil
			}
		},
		UpdateSecretVersionStageFunc: func(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
			updateSecretVersionCalled = true
			return nil, nil
		},
	}
	expectedUser := "foo"
	expectedSecret := "p2"

	ss := test.MockSecretSetter{
		CredentialsFunc: func(secret map[string]string) (string, string) {
			switch secret["v"] {
			case "1":
				return expectedUser, "p1"
			case "2":
				return expectedUser, expectedSecret
			case "0":
				return expectedUser, "p0"
			default:
				return "credUser", "credPass"
			}
		},
	}

	var gotUsername, gotPassword string
	ps := test.MockPasswordSetter{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotUsername = creds.New.Username
			gotPassword = creds.New.Password
			return nil
		},
		VerifyPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			if creds.New.Password == expectedSecret {
				return fmt.Errorf("fail to get to set password")
			}
			return nil
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   ss,
		PasswordSetter: ps,
	})

	// Simulate setSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "setSecret",
	}
	_, err := r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}

	if gotUsername != "foo" {
		t.Errorf("got username %s, expected \"foo\"", gotUsername)
	}
	if gotPassword != "p2" {
		t.Errorf("got password %s, expected \"p2\"", gotPassword)
	}

	// The code should not call UpdateSecretVersionStage. That doesn't happen
	// until the last step.
	if updateSecretVersionCalled {
		t.Errorf("UpdateSecretVersionStage called, expected no call by CreateSecret")
	}

	// ----------------------------------------------------------------------

	// The code caches secrets by stage to save money on AWS API calls.
	// We should have the first 2 calls from above:
	if nCallsToGetSecretValue != 2 {
		t.Errorf("GetSecretValue called %d times, expected 2", nCallsToGetSecretValue)
	}

	// Then if run the step again, the number of calls to GetSecretValue
	// should not increase because the code uses cached values:
	_, err = r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}
	if nCallsToGetSecretValue != 4 {
		t.Errorf("GetSecretValue called %d times, expected 4", nCallsToGetSecretValue)
	}
}

func TestStepSetSecret_DBAlreadySetToPending(t *testing.T) {
	// Test that the "setSecret" step gets both secrets (current and pending),
	// gets the db creds from pending, and sets them via PasswordSetter. This is
	// the second step in the four-step process.
	var updateSecretVersionCalled bool
	var nCallsToGetSecretValue int

	// Create mock Secrets Manager client (mock AWS API calls) and SecretSetter
	// (mock user-provided one)
	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			nCallsToGetSecretValue++
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v2"),
					VersionStages: []*string{aws.String(rotate.AWSPENDING)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPREVIOUS:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v0"),
					VersionStages: []*string{aws.String(rotate.AWSPREVIOUS)},
					CreatedDate:   &now,
				}, nil
			default:
				return nil, nil
			}
		},
		UpdateSecretVersionStageFunc: func(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
			updateSecretVersionCalled = true
			return nil, nil
		},
	}
	expectedUser := "foo"
	expectedSecret := "p2"

	ss := test.MockSecretSetter{
		CredentialsFunc: func(secret map[string]string) (string, string) {
			switch secret["v"] {
			case "1":
				return expectedUser, "p1"
			case "2":
				return expectedUser, expectedSecret
			case "0":
				return expectedUser, "p0"
			default:
				return "credUser", "credPass"
			}
		},
	}

	var gotUsername, gotPassword string
	ps := test.MockPasswordSetter{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotUsername = creds.New.Username
			gotPassword = creds.New.Password
			return nil
		},
		VerifyPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {

			return nil
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   ss,
		PasswordSetter: ps,
	})

	// Simulate setSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "setSecret",
	}
	_, err := r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}

	if gotUsername != "" {
		t.Errorf("got username %s, expected \"\"", gotUsername)
	}
	if gotPassword != "" {
		t.Errorf("got password %s, expected \"\"", gotPassword)
	}

	// The code should not call UpdateSecretVersionStage. That doesn't happen
	// until the last step.
	if updateSecretVersionCalled {
		t.Errorf("UpdateSecretVersionStage called, expected no call by CreateSecret")
	}

	// ----------------------------------------------------------------------

	// The code caches secrets by stage to save money on AWS API calls.
	// We should have the first 2 calls from above:
	if nCallsToGetSecretValue != 2 {
		t.Errorf("GetSecretValue called %d times, expected 2", nCallsToGetSecretValue)
	}

	// Then if run the step again, the number of calls to GetSecretValue
	// should not increase because the code uses cached values:
	_, err = r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}
	if nCallsToGetSecretValue != 4 {
		t.Errorf("GetSecretValue called %d times, expected 4", nCallsToGetSecretValue)
	}
}

func TestStepSetSecret_DBSetToPrevoius(t *testing.T) {
	// Test that the "setSecret" step gets both secrets (current and pending),
	// gets the db creds from pending, and sets them via PasswordSetter. This is
	// the second step in the four-step process.
	var updateSecretVersionCalled bool
	var nCallsToGetSecretValue int

	// Create mock Secrets Manager client (mock AWS API calls) and SecretSetter
	// (mock user-provided one)
	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			nCallsToGetSecretValue++
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v2"),
					VersionStages: []*string{aws.String(rotate.AWSPENDING)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPREVIOUS:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString0,
					VersionId:     aws.String("v0"),
					VersionStages: []*string{aws.String(rotate.AWSPREVIOUS)},
					CreatedDate:   &now,
				}, nil
			default:
				return nil, nil
			}
		},
		UpdateSecretVersionStageFunc: func(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
			updateSecretVersionCalled = true
			return nil, nil
		},
	}
	expectedUser := "foo"
	expectedSecret := "p2"
	previousSecret := "p0"
	ss := test.MockSecretSetter{
		CredentialsFunc: func(secret map[string]string) (string, string) {
			switch secret["v"] {
			case "1":
				return expectedUser, "p1"
			case "2":
				return expectedUser, expectedSecret
			case "0":
				return expectedUser, previousSecret
			default:
				return "credUser", "credPass"
			}
		},
	}
	verifiedNewPassword := []string{}
	verifiedOldPassword := []string{}
	expectedNewPassword := []string{"p2", "p1", "p0"}
	expectedOldPassword := []string{"p1", "p1", "p0"}

	var gotUsername, gotPassword string
	ps := test.MockPasswordSetter{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotUsername = creds.New.Username
			gotPassword = creds.New.Password
			return nil
		},
		VerifyPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			verifiedNewPassword = append(verifiedNewPassword, creds.New.Password)
			verifiedOldPassword = append(verifiedOldPassword, creds.Current.Password)
			if creds.Current.Password != previousSecret {
				return fmt.Errorf("expected to error")
			}
			return nil
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   ss,
		PasswordSetter: ps,
	})

	// Simulate setSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "setSecret",
	}
	_, err := r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}

	if gotUsername != expectedUser {
		t.Errorf("got username %s, expected \"%v\"", gotUsername, expectedUser)
	}
	if gotPassword != expectedSecret {
		t.Errorf("got password %s, expected \"%v\"", gotPassword, expectedSecret)
	}
	if diff := deep.Equal(expectedNewPassword, verifiedNewPassword); diff != nil {
		t.Errorf("unexpected diff in new password verification: %v", diff)
	}

	if diff := deep.Equal(expectedOldPassword, verifiedOldPassword); diff != nil {
		t.Errorf("unexpected diff in current password verification: %v", diff)
	}

	// The code should not call UpdateSecretVersionStage. That doesn't happen
	// until the last step.
	if updateSecretVersionCalled {
		t.Errorf("UpdateSecretVersionStage called, expected no call by CreateSecret")
	}

	// ----------------------------------------------------------------------

	// The code caches secrets by stage to save money on AWS API calls.
	// We should have the first 2 calls from above:
	if nCallsToGetSecretValue != 3 {
		t.Errorf("GetSecretValue called %d times, expected 2", nCallsToGetSecretValue)
	}

	// Then if run the step again, the number of calls to GetSecretValue
	// should not increase because the code uses cached values:
	_, err = r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}
	if nCallsToGetSecretValue != 6 {
		t.Errorf("GetSecretValue called %d times, expected 4", nCallsToGetSecretValue)
	}
}

func TestStepSetSecret_DBMismatch(t *testing.T) {
	// Test that the "setSecret" step gets both secrets (current and pending),
	// gets the db creds from pending, and sets them via PasswordSetter. This is
	// the second step in the four-step process.
	var updateSecretVersionCalled bool
	var nCallsToGetSecretValue int

	// Create mock Secrets Manager client (mock AWS API calls) and SecretSetter
	// (mock user-provided one)
	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			nCallsToGetSecretValue++
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v2"),
					VersionStages: []*string{aws.String(rotate.AWSPENDING)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPREVIOUS:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString0,
					VersionId:     aws.String("v0"),
					VersionStages: []*string{aws.String(rotate.AWSPREVIOUS)},
					CreatedDate:   &now,
				}, nil
			default:
				return nil, nil
			}
		},
		UpdateSecretVersionStageFunc: func(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
			updateSecretVersionCalled = true
			return nil, nil
		},
	}
	expectedUser := "foo"
	expectedSecret := "p2"
	previousSecret := "p0"
	ss := test.MockSecretSetter{
		CredentialsFunc: func(secret map[string]string) (string, string) {
			switch secret["v"] {
			case "1":
				return expectedUser, "p1"
			case "2":
				return expectedUser, expectedSecret
			case "0":
				return expectedUser, previousSecret
			default:
				return "credUser", "credPass"
			}
		},
	}

	var gotUsername, gotPassword string
	ps := test.MockPasswordSetter{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotUsername = creds.New.Username
			gotPassword = creds.New.Password
			return nil
		},
		VerifyPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			return fmt.Errorf("expected to error")
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   ss,
		PasswordSetter: ps,
	})

	// Simulate setSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "setSecret",
	}
	_, err := r.Handler(context.TODO(), event)
	if err == nil {
		t.Error(err)
	}

	if gotUsername != "" {
		t.Errorf("got username %s, expected \"\"", gotUsername)
	}
	if gotPassword != "" {
		t.Errorf("got password %s, expected \"\"", gotPassword)
	}

	// The code should not call UpdateSecretVersionStage. That doesn't happen
	// until the last step.
	if updateSecretVersionCalled {
		t.Errorf("UpdateSecretVersionStage called, expected no call by CreateSecret")
	}

	// ----------------------------------------------------------------------

	// The code caches secrets by stage to save money on AWS API calls.
	// We should have the first 2 calls from above:
	if nCallsToGetSecretValue != 3 {
		t.Errorf("GetSecretValue called %d times, expected 2", nCallsToGetSecretValue)
	}

	// Then if run the step again, the number of calls to GetSecretValue
	// should not increase because the code uses cached values:
	_, err = r.Handler(context.TODO(), event)
	if err == nil {
		t.Error(err)
	}
	if nCallsToGetSecretValue != 6 {
		t.Errorf("GetSecretValue called %d times, expected 4", nCallsToGetSecretValue)
	}
}

func TestStepTestSecret(t *testing.T) {
	// Test that the "testSecret" step does almost the exact same calls as previous
	// test for "setSecret" step. Only diff now: PasswordSetter.VerifyPassword()
	// instead of PasswordSetter.SetPassword().
	var updateSecretVersionCalled bool
	var nCallsToGetSecretValue int

	// Create mock Secrets Manager client (mock AWS API calls) and SecretSetter
	// (mock user-provided one)
	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			nCallsToGetSecretValue++
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v2"),
					VersionStages: []*string{aws.String(rotate.AWSPENDING)},
					CreatedDate:   &now,
				}, nil
			default:
				return nil, nil
			}
		},
		UpdateSecretVersionStageFunc: func(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
			updateSecretVersionCalled = true
			return nil, nil
		},
	}

	ss := test.MockSecretSetter{
		CredentialsFunc: func(secret map[string]string) (string, string) {
			switch secret["v"] {
			case "1":
				return "foo", "p1"
			case "2":
				return "foo", "p2"
			default:
				return "credUser", "credPass"
			}
		},
	}

	var gotUsername, gotPassword string
	setPasswordCalled := false
	ps := test.MockPasswordSetter{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			setPasswordCalled = true
			return nil
		},
		VerifyPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotUsername = creds.New.Username
			gotPassword = creds.New.Password
			return nil
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   ss,
		PasswordSetter: ps,
	})

	// Simulate testSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "testSecret",
	}
	_, err := r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}

	// This step should call VerifyPassword not SetPassword
	if setPasswordCalled {
		t.Error("SetPassword called in testSecret step, expected no call")
	}

	if gotUsername != "foo" {
		t.Errorf("got username %s, expected \"foo\"", gotUsername)
	}
	if gotPassword != "p2" {
		t.Errorf("got password %s, expected \"p2\"", gotPassword)
	}

	// The code should not call UpdateSecretVersionStage. That doesn't happen
	// until the last step.
	if updateSecretVersionCalled {
		t.Errorf("UpdateSecretVersionStage called, expected no call by CreateSecret")
	}
}

func TestStepFinishSecret(t *testing.T) {
	// Test that the "finishSecret" gets both sercets (current and pending) and
	// calls UpdateSecretVersionStage to move the current label to the pending
	// secret by ID.
	var gotUpdateInput *secretsmanager.UpdateSecretVersionStageInput
	var gotDescribeInput *secretsmanager.DescribeSecretInput
	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v2"),
					VersionStages: []*string{aws.String(rotate.AWSPENDING)},
					CreatedDate:   &now,
				}, nil
			default:
				return nil, nil
			}
		},
		UpdateSecretVersionStageFunc: func(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
			gotUpdateInput = input
			return &secretsmanager.UpdateSecretVersionStageOutput{
				ARN:  aws.String("arn"),
				Name: aws.String("sercetName"),
			}, nil
		},
		DescribeSecretFunc: func(input *secretsmanager.DescribeSecretInput) (*secretsmanager.DescribeSecretOutput, error) {
			gotDescribeInput = input
			return &secretsmanager.DescribeSecretOutput{}, nil
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   test.MockSecretSetter{},
		PasswordSetter: test.MockPasswordSetter{},
	})

	// Simulate testSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "finishSecret",
	}
	_, err := r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}

	expectUpdateInput := &secretsmanager.UpdateSecretVersionStageInput{
		SecretId:            aws.String("def"),
		RemoveFromVersionId: aws.String("v1"),
		MoveToVersionId:     aws.String("v2"),
		VersionStage:        aws.String(rotate.AWSCURRENT),
	}
	if diff := deep.Equal(gotUpdateInput, expectUpdateInput); diff != nil {
		t.Log(diff)
	}
	expectedDescribeInput := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String("def"),
	}
	if diff := deep.Equal(expectedDescribeInput, gotDescribeInput); diff != nil {
		t.Log(diff)
	}
}

func TestStepFinishSecretFailure(t *testing.T) {
	// Test that finish secret fails when describesecret replication status
	// does not go to InSync
	retryWait := 1 * time.Second

	sm := test.MockSecretsManager{
		GetSecretValueFunc: func(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
			switch *input.VersionStage {
			case rotate.AWSCURRENT:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString1,
					VersionId:     aws.String("v1"),
					VersionStages: []*string{aws.String(rotate.AWSCURRENT)},
					CreatedDate:   &now,
				}, nil
			case rotate.AWSPENDING:
				return &secretsmanager.GetSecretValueOutput{
					ARN:           aws.String("arn"),
					Name:          aws.String("sercetName"),
					SecretString:  &secretString2,
					VersionId:     aws.String("v2"),
					VersionStages: []*string{aws.String(rotate.AWSPENDING)},
					CreatedDate:   &now,
				}, nil
			default:
				return nil, nil
			}
		},
		UpdateSecretVersionStageFunc: func(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
			return &secretsmanager.UpdateSecretVersionStageOutput{
				ARN:  aws.String("arn"),
				Name: aws.String("sercetName"),
			}, nil
		},
		DescribeSecretFunc: func(input *secretsmanager.DescribeSecretInput) (*secretsmanager.DescribeSecretOutput, error) {
			return &secretsmanager.DescribeSecretOutput{
				ReplicationStatus: []*secretsmanager.ReplicationStatusType{
					&secretsmanager.ReplicationStatusType{
						Region: aws.String("us-west-2"),
						Status: aws.String(secretsmanager.StatusTypeInProgress),
					},
				},
			}, nil
		},
	}
	startTime := time.Now()
	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager:  sm,
		SecretSetter:    test.MockSecretSetter{},
		PasswordSetter:  test.MockPasswordSetter{},
		ReplicationWait: retryWait,
	})

	// Simulate testSecret event from Secrets Manager
	event := map[string]string{
		"ClientRequestToken": "abc",
		"SecretId":           "def",
		"Step":               "finishSecret",
	}
	_, err := r.Handler(context.TODO(), event)

	// expect an error
	if err == nil {
		t.Error(err)
	}

	finishTime := time.Now()
	testDuration := finishTime.Sub(startTime)
	if testDuration < retryWait {
		t.Errorf("expected test to take %v duration but it finished in %v", retryWait, testDuration)
	}
}

func TestUserInvoke(t *testing.T) {
	// Test that when the user invokes the lambda, not Secrets Manager, the
	// SecretSetter.Handler method is called and its return value is returned

	sm := test.MockSecretsManager{} // don't need funcs because this shouldn't be called

	// Thiso is called and returned:
	ret := map[string]string{"hello": "world"}
	ss := test.MockSecretSetter{
		HandlerFunc: func(ctx context.Context, event map[string]string) (map[string]string, error) {
			return ret, nil
		},
	}

	// Create a new Rotator to test
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: sm,
		SecretSetter:   ss,
		PasswordSetter: test.MockPasswordSetter{},
	})

	// Simulate an event NOT from Secrets Manager (see InvokedBySecretsManager())
	event := map[string]string{"knock": "knock"}
	got, err := r.Handler(context.TODO(), event)
	if err != nil {
		t.Error(err)
	}
	if diff := deep.Equal(got, ret); diff != nil {
		t.Log(diff)
	}
}
