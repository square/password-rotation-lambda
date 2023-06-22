// Copyright 2020, Square, Inc.

package rotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"

	"github.com/square/password-rotation-lambda/v2/db"
)

const (
	AWSCURRENT = "AWSCURRENT"
	AWSPENDING = "AWSPENDING"
)

func init() {
	// Don't need data/time because CloudWatch Logs adds it, avoid redundant output:
	//   2020-12-17T15:28:55.547-05:00	2020/12/17 20:28:55.547200 setter.go:79: Init call
	// First timestamp from CloudWatch, second from log.
	log.SetFlags(log.Lshortfile)
}

var (
	// ErrInvalidStep is returned if the "Step" value in the Secrets Manager event
	// is not one of "createSecret", "setSecret", "testSecret", or "finishSecret".
	ErrInvalidStep = errors.New("invalid Step value from event")
)

// Config represents the user-provided configuration for a Rotator.
type Config struct {
	// SecretsManager is an AWS Secrets Manager client. Create one by calling
	// secretsmanager.New() using package github.com/aws/aws-sdk-go/service/secretsmanager.
	// See https://pkg.go.dev/github.com/aws/aws-sdk-go@v1.30.4/service/secretsmanager?tab=doc#SecretsManager
	// for more details. The client implements this data type.
	SecretsManager secretsmanageriface.SecretsManagerAPI

	// SecretSetter manages the secret value and rotates the password. This is
	// the most important user-provided object. If none is provided, RandomPassword
	// is used. See SecretSetter for more details.
	SecretSetter SecretSetter

	// PasswordSetter sets the new, rotated password on databases. Implementations
	// are provided in the db/ directory.
	PasswordSetter db.PasswordSetter

	// SkipDatabase skips setting the the new, rotated password on databases if true
	// but does all the other work. If there is a database issue that blocks a
	// Secrets Manager rotation, this lets the Secrets Manager rotation complete.
	// Normally, this should be false; only set to true when knowingly fixing an issue
	// that requires it.
	SkipDatabase bool

	// EventReceiver receives events during the four-step password rotation process.
	// If none is provided, NullEventReceiver is used. See EventReceiver for more details.
	EventReceiver EventReceiver

	// ReplicationWaitDuration governs the duration password rotation lambda will wait for
	// secret replication to secondary regions to complete
	ReplicationWaitDuration time.Duration
}

// InvokedBySecretsManager returns true if the event is from Secrets Manager.
func InvokedBySecretsManager(event map[string]string) bool {
	_, haveToken := event["ClientRequestToken"]
	_, haveSecretId := event["SecretId"]
	_, haveStep := event["Step"]
	return haveToken && haveSecretId && haveStep
}

// Generic return error because errors are logged when/whey they occur so the log
// output in CloudWatch Logs reads in the correct order.  Lambda logs the return
// error last, of course, which makes it appear after "SetSecret return:" logs in
// from defer funcs.
var errRotationFailed = errors.New("Password rotation failed, see previous log output")

// Rotator is the AWS Lambda function and handler. Create a new Rotator by
// calling NewRotator, then use it in your main.go by calling lambda.Start(r.Handler)
// where "r" is the new Rotator. See the documentation and examples for more details.
//
// Currently, only secret string, not secret binary, is used and it must be
// a JSON string with key-value pairs. See SecretSetter for details.
type Rotator struct {
	sm     secretsmanageriface.SecretsManagerAPI
	ss     SecretSetter
	db     db.PasswordSetter
	event  EventReceiver
	skipDb bool
	// --
	clientRequestToken      string
	secretId                string
	startTime               time.Time
	replicationWaitDuration time.Duration
}

// NewRotator creates a new Rotator.
func NewRotator(cfg Config) *Rotator {
	event := cfg.EventReceiver
	if event == nil {
		event = NullEventReceiver{}
	}
	if cfg.EventReceiver == nil {
		cfg.EventReceiver = NullEventReceiver{}
	}
	ss := cfg.SecretSetter
	if ss == nil {
		ss = RandomPassword{}
	}
	return &Rotator{
		sm:                      cfg.SecretsManager,
		db:                      cfg.PasswordSetter,
		ss:                      ss,
		event:                   event,
		skipDb:                  cfg.SkipDatabase,
		replicationWaitDuration: cfg.ReplicationWaitDuration,
	}
}

// Handler is the entry point for every invocation. This function is hooked into
// the Lambda framework by calling lambda.Start(r.Handler) where "r" is the Rotator
// returned by NewRotator.
//
// Use only this function. The other Rotator functions are exported only for testing.
func (r *Rotator) Handler(ctx context.Context, event map[string]string) (map[string]string, error) {
	if !InvokedBySecretsManager(event) {
		debug("user event: %+v", event)
		return r.ss.Handler(ctx, event)
	}

	debug("Secrets Manager event: %+v", event)

	// Initialize user-provided SecretSetter and PasswordSetter. On first call
	// (invocation), these should set up any internal data, e.g. find and connect
	// to all the db instances. These must be idempotent because we don't know
	// if the lambda is resuming or not.
	if err := r.ss.Init(ctx, event); err != nil {
		return nil, err
	}
	if err := r.db.Init(ctx, event); err != nil {
		return nil, err
	}

	r.clientRequestToken = event["ClientRequestToken"]
	r.secretId = event["SecretId"]
	step := event["Step"]
	var err error
	switch step {
	case "createSecret":
		err = r.CreateSecret(ctx, event)
	case "setSecret":
		err = r.SetSecret(ctx, event)
	case "testSecret":
		err = r.TestSecret(ctx, event)
	case "finishSecret":
		err = r.FinishSecret(ctx, event)
	default:
		return nil, ErrInvalidStep
	}

	if err != nil {
		r.event.Receive(Event{
			Name:  EVENT_ERROR,
			Time:  time.Now(),
			Step:  step,
			Error: err,
		})
	}
	return nil, err
}

// CreateSecret is the first step in the Secrets Manager rotation process.
//
// Do not call this function directly. It is exported only for testing.
func (r *Rotator) CreateSecret(ctx context.Context, event map[string]string) error {
	t0 := time.Now()
	log.Println("CreateSecret call")
	defer func() {
		d := time.Now().Sub(t0)
		log.Printf("CreateSecret return: %dms", d.Milliseconds())
	}()

	/*
		In the simplest case, there's one secret with AWSCURRENT and nothing
		else (we can ignore any secrets without stages or ASWPREVIOUS). So we
		create our new secret with the AWSPENDING staging label and we're done.
		But in the real world we have to handle various edge cases:

		1) Current secret has pending label because:

			(Optional) Remove the label AWSPENDING from its version of the secret.
			https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-one-user-one-password.html

		This is ok as long as current secret and our (new) secret have different
		version IDs, i.e. they're different secrets.

		2) There's a pending secret and it's ours. This can happen because this
		(and every) step can be retried. This is ok, too, as long as the pending
		secret is our secret (i.e. have same version ID). We can re-create because
		it's idempotent as long as the secret values are the same.

		3) There's a pending secret and it's _not_ ours. This is an unrecoverable
		error. It could happen if another process tries to rotate the same secret
		at the same time.

		4) Our secret is already current. This shouldn't happen, but it could
		if someone manually changes staging labels with the AWS CLI.

		"Our secret" = r.clientRequestToken, i.e. it's identified by the client
		request token which "becomes the SecretVersionId of the new version of
		the secret."
		https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-lambda-function-overview.html
	*/

	r.event.Receive(Event{
		Name: EVENT_BEGIN_ROTATION,
		Step: "createSecret",
		Time: time.Now(),
	})

	// Get current secret
	curSec, curVals, err := r.getSecret(AWSCURRENT)
	if err != nil {
		return err
	}

	// Case 4:
	// Is our secret the current secret? It shouldn't be.
	if r.clientRequestToken == *curSec.VersionId {
		return fmt.Errorf("new and current secret have the same version ID: %s; expected different values", r.clientRequestToken)
	}

	// Case 1:
	// Does the current secret also have the pending stage? It can because
	// removing it from previous runs is optional. Loop through the current's
	// stages to check for pending.
	currentHasPending := false
	for _, label := range curSec.VersionStages {
		if *label == AWSPENDING {
			debug("current secret has AWSPENDING stage")
			currentHasPending = true
			break
		}
	}

	// If the current doesn't have pending label, then check for any pending secret.
	// If there's _not_ a pending secret, then we'll rotate the current secret.
	// If there is a pending secret and it's ours (due to a retry), then we'll
	// use its values and not rotate.
	if !currentHasPending {
		penSec, _, err := r.getSecret(AWSPENDING)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok && aerr.Code() == secretsmanager.ErrCodeResourceNotFoundException {
				// *** The simplest case ***
				// No secret has the pending staging label. This is probably the
				// very first invocation, so we can just create our new secret.
				debug("no pending secret, will rotate current secret")
			} else {
				return err
			}
		} else {
			if *penSec.VersionId == r.clientRequestToken {
				// Case 2:
				// There's a pending secret and it's our. This must be a retry.
				// We do not and cannot rotate the values, else PutSecretValue
				// will error. It's only idempotent with the same values.
				debug("using pending secret, will not rotate")

				// Return early, nothing more to do. Code below is for rotating
				// current values, but we already did that in previous try.
				return nil
			} else {
				// Case 3:
				// There's a pending secret and it's not ours. Something (or someone)
				// else is rotating this secret at the same time.
				debug("pending secret has different version id = %s", *penSec.VersionId)
				return fmt.Errorf("another pending secret exists (version ID %s); "+
					" another process might be rotating this secret, or a previous rotation failed without cleaning up", *penSec.VersionId)
			}
		}
	}

	// ----------------------------------------------------------------------
	// Code reaches here if current has pending or no secret has pending.
	// This is normal case when we need to create new pending secret from
	// rotated current values.
	debug("rotating current secret")

	// MUST COPY curVals to avoid changing cache (r.secets.values) because
	// r.ss.Rotate() modifies the map
	newVals := map[string]string{}
	for k, v := range curVals {
		newVals[k] = v
	}

	// Have user-provided SecretSetter rotate the secret. Normally, it should
	// just change the password, but it's free to change any secret values.
	if err := r.ss.Rotate(newVals); err != nil {
		return err
	}
	debugSecret("new secret values: %v", newVals)

	// Convert secret JSON to string
	bytes, err := json.Marshal(newVals)
	if err != nil {
		return err
	}

	// Set new secret as PENDING, i.e. current secret has not changed yet.
	// We'll set and test the new secret values in the next two steps.
	output, err := r.sm.PutSecretValue(&secretsmanager.PutSecretValueInput{
		ClientRequestToken: aws.String(r.clientRequestToken),
		SecretId:           aws.String(r.secretId),
		SecretString:       aws.String(string(bytes)),
		VersionStages:      []*string{aws.String(AWSPENDING)}, // must be AWSPENDING
	})
	if err != nil {
		return err
	}
	log.Printf("new pending secret metadata: %+v", *output)

	return nil
}

// SetSecret is the second step in the Secrets Manager rotation process.
//
// Do not call this function directly. It is exported only for testing.
func (r *Rotator) SetSecret(ctx context.Context, event map[string]string) error {
	t0 := time.Now()
	log.Println("SetSecret call")
	defer func() {
		d := time.Now().Sub(t0)
		log.Printf("SetSecret return: %dms", d.Milliseconds())
	}()

	if r.skipDb {
		log.Println("SkipDatabase is enabled, not rotating password on database")
		return nil
	}

	// Get new, pending secret values from previous (first) step. Then have
	// user-provided SecretSetter return the new user and pass from the secret.
	_, newVals, err := r.getSecret(AWSPENDING)
	if err != nil {
		return err
	}
	newUsername, newPassword := r.ss.Credentials(newVals)

	// And get current secret values in case setting new fails and we to roll back
	_, curVals, err := r.getSecret(AWSCURRENT)
	if err != nil {
		return err
	}
	curUsername, curPassword := r.ss.Credentials(curVals)

	// Combine the current and new credentials. This is plumbed all the way down
	// into the db.PassswordSetter implementation.
	creds := db.NewPassword{
		Current: db.Credentials{
			Username: curUsername,
			Password: curPassword,
		},
		New: db.Credentials{
			Username: newUsername,
			Password: newPassword,
		},
	}
	debugSecret("db credentials: %+v", creds)

	// Have user-provided PasswordSetter set database password to new value.
	// Normally, this is when the database password actually changes.
	// The PasswordSetter is responsible for knowing which db instances to change.
	// mysql.PasswordSetter, for example, sets every RDS instance in parallel.
	r.startTime = time.Now()
	r.event.Receive(Event{
		Name: EVENT_BEGIN_PASSWORD_ROTATION,
		Step: "setSecret",
		Time: r.startTime,
	})
	if err := r.db.SetPassword(ctx, creds); err != nil {
		// Roll back to original password since setting the new password failed.
		// Depending on how the PasswordSetter is configured, this might be a no-op.
		// Normally, we want to roll back so all dbs instances have the same
		// password for the given user.
		log.Printf("ERROR: SetPassword failed, rollback: %s", err)
		r.event.Receive(Event{
			Name: EVENT_BEGIN_PASSWORD_ROLLBACK,
			Step: "setSecret",
			Time: time.Now(),
		})
		return r.rollback(ctx, creds, "SetSecret")
	}
	r.event.Receive(Event{
		Name: EVENT_END_PASSWORD_ROTATION,
		Step: "setSecret",
		Time: r.startTime,
	})

	// At this point, the db password has been changed, but AWS Secrets Manager
	// still returns the old password. The next step verifies the new password,
	// and the fourth and final step makes the new password current in Secrets Manager.
	return nil
}

// TestSecret is the third step in the Secrets Manager rotation process.
//
// Do not call this function directly. It is exported only for testing.
func (r *Rotator) TestSecret(ctx context.Context, event map[string]string) error {
	t0 := time.Now()
	log.Println("TestSecret call")
	defer func() {
		d := time.Now().Sub(t0)
		log.Printf("TestSecret return: %dms", d.Milliseconds())
	}()

	if r.skipDb {
		log.Println("SkipDatabase is enabled, not verifying password on database")
		return nil
	}

	// Get new, pending secret values from previous (first) step. Then have
	// user-provided SecretSetter return the new user and pass from the secret.
	_, newVals, err := r.getSecret(AWSPENDING)
	if err != nil {
		return err
	}
	newUsername, newPassword := r.ss.Credentials(newVals)

	// And get current secret values in case setting new fails and we to roll back
	_, curVals, err := r.getSecret(AWSCURRENT)
	if err != nil {
		return err
	}
	curUsername, curPassword := r.ss.Credentials(curVals)

	// Combine the current and new credentials. This is plumbed all the way down
	// into the db.PassswordSetter implementation.
	creds := db.NewPassword{
		Current: db.Credentials{
			Username: curUsername,
			Password: curPassword,
		},
		New: db.Credentials{
			Username: newUsername,
			Password: newPassword,
		},
	}
	debugSecret("db credentials: %+v", creds)

	// Have user-provided PasswordSetter verify that new database password works
	r.event.Receive(Event{
		Name: EVENT_BEGIN_PASSWORD_VERIFICATION,
		Step: "testSecret",
		Time: time.Now(),
	})
	if err := r.db.VerifyPassword(ctx, creds); err != nil {
		// Roll back to original password since new password doesn't work
		log.Printf("ERROR: VerifyPassword failed, rollback: %s", err)
		r.event.Receive(Event{
			Name: EVENT_BEGIN_PASSWORD_ROLLBACK,
			Step: "testSecret",
			Time: time.Now(),
		})
		return r.rollback(ctx, creds, "TestSecret")
	}
	r.event.Receive(Event{
		Name: EVENT_END_PASSWORD_VERIFICATION,
		Step: "testSecret",
		Time: time.Now(),
	})

	// At this point, AWS Secrets Manager still returns the old password.
	// The next and final step makes the new password current in Secrets Manager.
	return nil
}

// FinishSecret is the fourth and final step in the Secrets Manager rotation process.
//
// Do not call this function directly. It is exported only for testing.
func (r *Rotator) FinishSecret(ctx context.Context, event map[string]string) error {
	t0 := time.Now()
	log.Println("FinishSecret call")
	defer func() {
		d := time.Now().Sub(t0)
		log.Printf("FinishSecret return: %dms", d.Milliseconds())
	}()

	// Get current and new secrets so we can move the AWSPENDING/CURRENT label
	// by secret ID
	curSecret, _, err := r.getSecret(AWSCURRENT)
	if err != nil {
		return err
	}
	newSecret, _, err := r.getSecret(AWSPENDING)
	if err != nil {
		return err
	}

	// Move AWSCURRENT label from the current secret to the new. This makes the
	// new secret current and automatically labels the old secret "previous".
	debug("moving AWSCURRENT from version id = %v to version id = %v", *curSecret.VersionId, *newSecret.VersionId)
	_, err = r.sm.UpdateSecretVersionStage(&secretsmanager.UpdateSecretVersionStageInput{
		SecretId:            aws.String(r.secretId),
		RemoveFromVersionId: curSecret.VersionId,
		MoveToVersionId:     newSecret.VersionId,
		VersionStage:        aws.String(AWSCURRENT),
	})
	if err != nil {
		return err
	}
	now := time.Now()
	r.event.Receive(Event{
		Name: EVENT_NEW_PASSWORD_IS_CURRENT,
		Step: "finishSecret",
		Time: now,
	})

	downtime := now.Sub(r.startTime)
	log.Printf("password downtime: %dms", downtime.Milliseconds())

	// Wait for secret replication to complete to all replica regions
	err = r.checkSecretReplicationStatus()
	if err != nil {
		return err
	}

	// Remove AWSPENDING label
	debug("removing AWSPENDING from version id = %v", *newSecret.VersionId)
	_, err = r.sm.UpdateSecretVersionStage(&secretsmanager.UpdateSecretVersionStageInput{
		SecretId:            aws.String(r.secretId),
		RemoveFromVersionId: newSecret.VersionId,
		VersionStage:        aws.String(AWSPENDING),
	})
	if err != nil {
		log.Println(err)
	}

	r.event.Receive(Event{
		Name: EVENT_END_ROTATION,
		Step: "finishSecret",
		Time: time.Now(),
	})

	return nil
}

// --------------------------------------------------------------------------

func (r *Rotator) getSecret(stage string) (*secretsmanager.GetSecretValueOutput, map[string]string, error) {
	// Fetch secret from Secrets Manager
	s, err := r.sm.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(r.secretId),
		VersionStage: aws.String(stage),
	})
	if err != nil {
		return nil, nil, err
	}
	debug("%s stage %s version %v", r.secretId, stage, *s.VersionId)

	if s.SecretString == nil || *s.SecretString == "" {
		return s, nil, fmt.Errorf("secret string is nil or empty string; " +
			"it must be valid JSON like '{\"username\":\"foo\",\"password\":\"bar\"}'")
	}

	var v map[string]string
	if err := json.Unmarshal([]byte(*s.SecretString), &v); err != nil {
		return nil, nil, err
	}
	if v == nil {
		return s, nil, fmt.Errorf("secret string is 'null' literal; " +
			"it must be valid JSON like '{\"username\":\"foo\",\"password\":\"bar\"}'")
	}
	debugSecret("%s secret values: %v", stage, *s.SecretString)

	return s, v, nil
}

func (r *Rotator) rollback(ctx context.Context, creds db.NewPassword, rotationStep string) error {
	if err := r.db.Rollback(ctx, creds); err != nil {
		log.Printf("ERROR: Rollback failed: %s", err)
		return errRotationFailed
	}

	// Remove pending secret and clear the cache, i.e. roll back Secrets Manager
	// to point before this rotation
	newSecret, _, err := r.getSecret(AWSPENDING)
	if err != nil {
		return err
	}
	debug("removing AWSPENDING from version id = %v", *newSecret.VersionId)
	_, err = r.sm.UpdateSecretVersionStage(&secretsmanager.UpdateSecretVersionStageInput{
		SecretId:            aws.String(r.secretId),
		RemoveFromVersionId: newSecret.VersionId,
		VersionStage:        aws.String(AWSPENDING),
	})
	if err != nil {
		log.Printf("ERROR: failed to remove pending secret: %s", err)
		return errRotationFailed
	}

	log.Printf("%s failed but rollback was successful", rotationStep)

	return errRotationFailed // always return this error
}

// checks that secret have been replicated to all replica regions
// this is necessary between multiple calls of UpdateSecretVersionStage
// to guard against arace condition in AWS that leaves secret replication
// stuck indefinitely.
func (r *Rotator) checkSecretReplicationStatus() error {
	log.Println("checking secret replication status")
	waitDuration := DEFAULT_REPLICATION_WAIT_DURATION
	if r.replicationWaitDuration > 0 {
		waitDuration = r.replicationWaitDuration
	}

	startTime := time.Now()
	for time.Now().Sub(startTime) < waitDuration {
		secret, err := r.sm.DescribeSecret(&secretsmanager.DescribeSecretInput{
			SecretId: aws.String(r.secretId),
		})
		if err != nil {
			return err
		}
		if secret == nil {
			return fmt.Errorf("expected an non null secret for secretId %v but received null", r.secretId)
		}
		replicationSyncComplete := true
		for _, status := range secret.ReplicationStatus {
			if status == nil {
				continue
			}
			if *status.Status != secretsmanager.StatusTypeInSync {
				replicationSyncComplete = false
				log.Printf("replication status still in (%v) in region (%v) expecting (%v)\n", *status.Status, *status.Region, secretsmanager.StatusTypeInSync)
			}
		}
		if replicationSyncComplete {
			log.Println("secret replication sync completed successfully")
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for secret replication StatusTypeInSync = true")
}

// --------------------------------------------------------------------------

var (
	// Debug enables debug output to STDERR. It does not print secret values.
	// Debug lines start with "DEBUG". AWS Lambda usually logs all output to CloudWatch Logs.
	Debug = false

	// DebugSecret IS DANGEROUS: it prints secret values to STDERR when Debug is enabled.
	// If Debug is false (disabled), this value is ignored.
	//
	// Be very careful enabling this!
	DebugSecret = false

	debugLog = log.New(os.Stderr, "DEBUG ", log.LstdFlags|log.Lmicroseconds|log.Lshortfile|log.LUTC)

	// DEFAULT_REPLICATION_WAIT_DURATION is the default duration that password rotation lambda will
	// wait for secret replication to secondary regions to complete
	DEFAULT_REPLICATION_WAIT_DURATION = 10 * time.Second
)

func debugSecret(msg string, v ...interface{}) {
	if !Debug || !DebugSecret {
		return
	}
	_, file, line, _ := runtime.Caller(1)
	msg = fmt.Sprintf("%s:%d %s", path.Base(file), line, msg)
	debugLog.Printf(msg, v...)
}

func debug(msg string, v ...interface{}) {
	if !Debug {
		return
	}
	_, file, line, _ := runtime.Caller(1)
	msg = fmt.Sprintf("%s:%d %s", path.Base(file), line, msg)
	debugLog.Printf(msg, v...)
}
