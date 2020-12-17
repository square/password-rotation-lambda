// Copyright 2020, Square, Inc.

package mysql_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/go-test/deep"

	"github.com/square/password-rotation-lambda/v2/db"
	"github.com/square/password-rotation-lambda/v2/db/mysql"
	"github.com/square/password-rotation-lambda/v2/test"
)

func TestPasswordSetterOne(t *testing.T) {
	// Test that Init, SetPassword, and VerifyPassword make the right calls with
	// just one db instance

	// Mock the RDS client to return data that simulates have only 1 RDS instance
	var gotInput *rds.DescribeDBInstancesInput
	nRDSCalls := 0
	rdsClient := test.MockRDSClient{
		DescribeDBInstancesFunc: func(input *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
			nRDSCalls++
			gotInput = input
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []*rds.DBInstance{
					{
						DBInstanceArn:        aws.String("arn"),
						DBInstanceIdentifier: aws.String("db-1"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr:3306"),
							Port:    aws.Int64(3306),
						},
					},
				},
			}, nil
		},
	}

	// Mock the PasswordClient so we don't have to use a real MySQL/RDS instance
	gotCreds := []db.NewPassword{}
	gotVerified := []db.NewPassword{}
	mysqlClient := test.MockMySQLPasswordClient{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotCreds = append(gotCreds, creds)
			return nil
		},
		VerifyPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotVerified = append(gotVerified, creds)
			return nil
		},
	}

	// Create new PasswordSetter with bare minimum config
	cfg := mysql.Config{
		RDSClient: rdsClient,
		DbClient:  mysqlClient,
	}
	ps := mysql.NewPasswordSetter(cfg)

	// Always need to call Init first. Since Rotator can call it multiple times,
	// we'll also check that the number of calls to RDS remains 1.
	secret := map[string]string{}
	err := ps.Init(context.TODO(), secret)
	if err != nil {
		t.Error(err)
	}

	// Init should get all RDS instances
	expectInput := &rds.DescribeDBInstancesInput{} // all instances
	if diff := deep.Equal(gotInput, expectInput); diff != nil {
		t.Error(diff)
	}

	// Init should only call RDS API once. So we have count = 1 now, but call Init
	// again and verify that count stays = 1.
	if nRDSCalls != 1 {
		t.Errorf("RDS calls = %d, expected 1", nRDSCalls)
	}
	err = ps.Init(context.TODO(), secret)
	if err != nil {
		t.Error(err)
	}
	if nRDSCalls != 1 {
		t.Errorf("RDS calls = %d, expected 1", nRDSCalls)
	}

	// After Init, Rotator will call SetPassword to do the real work
	creds := db.NewPassword{
		Current: db.Credentials{
			Username: "user",
			Password: "old_pass",
			Hostname: "addr:3306",
		},
		New: db.Credentials{
			Username: "user",
			Password: "new_pass",
			Hostname: "addr:3306",
		},
	}
	err = ps.SetPassword(context.TODO(), creds)
	if err != nil {
		t.Error(err)
	}

	// Triple check that RDS was not called again
	if nRDSCalls != 1 {
		t.Errorf("RDS calls = %d, expected 1", nRDSCalls)
	}

	// SetPassword should call the PasswordClient with the mock username, password,
	// and RDS hostname, which our mock smashes together as one string
	expectCreds := []db.NewPassword{
		{
			Current: db.Credentials{Username: "user", Password: "old_pass", Hostname: "addr:3306"},
			New:     db.Credentials{Username: "user", Password: "new_pass", Hostname: "addr:3306"},
		},
	}
	if diff := deep.Equal(gotCreds, expectCreds); diff != nil {
		t.Error(diff)
	}

	// SetPassword should not call VerifyPassword. Rotator does that after calling
	// SetPassword.
	if diff := deep.Equal(gotVerified, []db.NewPassword{}); diff != nil {
		t.Error(diff)
	}

	// After SetPassword, Rotator calls VerifyPasssword. Note that it's passed
	// the user and pass again. Normally, this is the same user/pass that was
	// passed to SetPassword, but we'll change it to check this code's plumbing.
	// What does not change is the RDS addr because this is internal to the code.
	err = ps.VerifyPassword(context.TODO(), creds)
	if err != nil {
		t.Error(err)
	}

	if diff := deep.Equal(gotVerified, expectCreds); diff != nil {
		t.Error(diff)
	}
}

func TestPasswordSetterRetry(t *testing.T) {
	// Test that code will retry SetPassword. VerifyPassword uses same underlying
	// retry code, so we only need to test one of the two.

	// Mock the RDS client to return data that simulates have only 1 RDS instance
	rdsClient := test.MockRDSClient{
		DescribeDBInstancesFunc: func(input *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []*rds.DBInstance{
					{
						DBInstanceArn:        aws.String("arn"),
						DBInstanceIdentifier: aws.String("db-1"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr:3306"),
							Port:    aws.Int64(3306),
						},
					},
				},
			}, nil
		},
	}

	// Mock the PasswordClient so we can return an error on first 2 calls to trigger
	// the retry, then return successfully on the 3rd call
	nSetCalls := 0
	nCallsToFail := 2 // fail on first 2 tries
	gotCreds := []db.NewPassword{}
	mysqlClient := test.MockMySQLPasswordClient{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotCreds = append(gotCreds, creds)
			nSetCalls++
			if nSetCalls <= nCallsToFail {
				return fmt.Errorf("fake db error")
			}
			return nil
		},
	}

	// ----------------------------------------------------------------------
	// No retries

	// First let's make sure that, internally, tries = 1 + retries. So if user
	// don't configure any retries, they get only 1 try.

	// Create new PasswordSetter with bare minimum config (no Retry)
	cfg := mysql.Config{
		RDSClient: rdsClient,
		DbClient:  mysqlClient,
	}
	ps := mysql.NewPasswordSetter(cfg)

	// Always need to call Init first
	secret := map[string]string{}
	err := ps.Init(context.TODO(), secret)
	if err != nil {
		t.Error(err)
	}

	creds := db.NewPassword{
		Current: db.Credentials{
			Username: "user",
			Password: "old_pass",
			Hostname: "addr:3306",
		},
		New: db.Credentials{
			Username: "user",
			Password: "new_pass",
			Hostname: "addr:3306",
		},
	}
	err = ps.SetPassword(context.TODO(), creds)
	if err == nil {
		t.Errorf("SetPassword did not return an error, expected one")
	}

	// Because no retries, PasswordClient.SetPassword should only be called once.
	// Note: this is PasswordClient.SetPassword, not PasswordSetter.SetPassword.
	if nSetCalls != 1 {
		t.Errorf("SetPassword called %d times, expected 1", nSetCalls)
	}

	// ----------------------------------------------------------------------
	// With 2 retries

	// Now the more realistic test: 2 retries, so 3 tries total. And to test
	// the retry wait, we'll time the whole thing to ensure it takes roughly
	// the time we expect which is ~500s because 2x 250ms waits after tries
	// 1 and 2.
	nSetCalls = 0

	// Create new PasswordSetter with bare minimum config (no Retry)
	cfg = mysql.Config{
		RDSClient: rdsClient,
		DbClient:  mysqlClient,
		Retry:     2,
		RetryWait: time.Duration(250 * time.Millisecond),
	}
	ps = mysql.NewPasswordSetter(cfg)

	// Always need to call Init first
	err = ps.Init(context.TODO(), secret)
	if err != nil {
		t.Error(err)
	}

	t0 := time.Now()
	err = ps.SetPassword(context.TODO(), creds)
	msWaited := time.Now().Sub(t0).Milliseconds()
	if err != nil {
		t.Error(err)
	}

	// PasswordClient.SetPassword should be called 3 times: 1 fail, wait, retry;
	// 2 fail, wait, retry; 3 succeed
	if nSetCalls != 3 {
		t.Errorf("SetPassword called %d times, expected 3", nSetCalls)
	}

	// Timings aren't exact. If they were, it'd be 500ms, but in reality it'll be
	// around that number.
	if msWaited < 400 || msWaited > 600 {
		t.Errorf("waited %dms, expected 500ms +/- 100ms", msWaited)
	}

	// ----------------------------------------------------------------------
	// With 2 retries but fails

	// Same as before but test that code does, in fact, stop trying when
	// configured with retries
	nSetCalls = 0
	nCallsToFail = 4 // any number > 1+Retry

	ps = mysql.NewPasswordSetter(cfg)

	// Always need to call Init first
	err = ps.Init(context.TODO(), secret)
	if err != nil {
		t.Error(err)
	}

	t0 = time.Now()
	err = ps.SetPassword(context.TODO(), creds)
	msWaited = time.Now().Sub(t0).Milliseconds()

	// Expect an error
	if err == nil {
		t.Errorf("SetPassword did not return an error, expected one")
	}

	if nSetCalls != 3 {
		t.Errorf("SetPassword called %d times, expected 3", nSetCalls)
	}

	if msWaited < 400 || msWaited > 600 {
		t.Errorf("waited %dms, expected 500ms +/- 100ms", msWaited)
	}
}

func TestPasswordSetterFilterFunc(t *testing.T) {
	// Test that the user-provided filter func filters out RDS instances. Since
	// the final list is internal the PaswordSetter, we'll have to call SetPassword
	// to see the list.

	// Mock the RDS client to return 3 RDS instances, the first two we'll filter out
	rdsClient := test.MockRDSClient{
		DescribeDBInstancesFunc: func(input *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []*rds.DBInstance{
					{
						DBInstanceArn:        aws.String("arn1"),
						DBInstanceIdentifier: aws.String("db-1"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr1:3306"),
							Port:    aws.Int64(3306),
						},
					},
					{
						DBInstanceArn:        aws.String("arn2"),
						DBInstanceIdentifier: aws.String("db-2"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr2:3306"),
							Port:    aws.Int64(3306),
						},
					},

					{
						DBInstanceArn:        aws.String("arn3"),
						DBInstanceIdentifier: aws.String("db-3"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr3:3306"),
							Port:    aws.Int64(3306),
						},
					},
				},
			}, nil
		},
	}

	gotCreds := []db.NewPassword{}
	mysqlClient := test.MockMySQLPasswordClient{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotCreds = append(gotCreds, creds)
			return nil
		},
	}

	filter := func(in *rds.DBInstance) bool {
		// Keep only the last instance, filter out the first two
		return *in.Endpoint.Address != "addr3:3306"
	}

	// Create new PasswordSetter with a filter func
	cfg := mysql.Config{
		RDSClient: rdsClient,
		DbClient:  mysqlClient,
		Filter:    filter,
	}
	ps := mysql.NewPasswordSetter(cfg)

	// Always need to call Init first
	secret := map[string]string{}
	err := ps.Init(context.TODO(), secret)
	if err != nil {
		t.Error(err)
	}

	creds := db.NewPassword{
		Current: db.Credentials{
			Username: "user",
			Password: "old_pass",
			Hostname: "addr:3306",
		},
		New: db.Credentials{
			Username: "user",
			Password: "new_pass",
			Hostname: "addr:3306",
		},
	}
	err = ps.SetPassword(context.TODO(), creds)
	if err != nil {
		t.Error(err)
	}

	// We know the filter func worked because only addr3 was used
	expectCreds := []db.NewPassword{
		{
			Current: db.Credentials{Username: "user", Password: "old_pass", Hostname: "addr3:3306"},
			New:     db.Credentials{Username: "user", Password: "new_pass", Hostname: "addr3:3306"},
		},
	}
	if diff := deep.Equal(gotCreds, expectCreds); diff != nil {
		t.Error(diff)
	}
}

func TestPasswordSetterParallel(t *testing.T) {
	// Test that Config.Parallel runs that and only that many SetPasswords at once.
	// VerifyPassword uses the same underlying code, so only need to test one.
	//
	// To test this, we need to simulate a slow db. Since the db calls are done
	// in the PasswordClient, we'll use our mock to block execution of SetPassword.
	// If Parallel works, we'll have at most only Parallel-number of blocked
	// PasswordClient at once.

	// Mock the RDS client to return 3 RDS instances, and we'll run 2 in parallel
	rdsClient := test.MockRDSClient{
		DescribeDBInstancesFunc: func(input *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []*rds.DBInstance{
					{
						DBInstanceArn:        aws.String("arn1"),
						DBInstanceIdentifier: aws.String("db-1"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr1:3306"),
							Port:    aws.Int64(3306),
						},
					},
					{
						DBInstanceArn:        aws.String("arn2"),
						DBInstanceIdentifier: aws.String("db-2"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr2:3306"),
							Port:    aws.Int64(3306),
						},
					},

					{
						DBInstanceArn:        aws.String("arn3"),
						DBInstanceIdentifier: aws.String("db-3"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr3:3306"),
							Port:    aws.Int64(3306),
						},
					},
				},
			}, nil
		},
	}

	unblockDb := make(chan bool, 1)
	mux := &sync.Mutex{}
	dbsRunning := 0
	mysqlClient := test.MockMySQLPasswordClient{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			mux.Lock()
			dbsRunning += 1
			mux.Unlock()

			defer func() {
				mux.Lock()
				dbsRunning -= 1
				mux.Unlock()
			}()

			<-unblockDb
			return nil
		},
	}

	// Create new PasswordSetter with Parallel=2
	cfg := mysql.Config{
		RDSClient: rdsClient,
		DbClient:  mysqlClient,
		Parallel:  2,
	}
	ps := mysql.NewPasswordSetter(cfg)

	// Always need to call Init first
	secret := map[string]string{}
	err := ps.Init(context.TODO(), secret)
	if err != nil {
		t.Error(err)
	}

	creds := db.NewPassword{
		Current: db.Credentials{
			Username: "user",
			Password: "old_pass",
			Hostname: "addr:3306",
		},
		New: db.Credentials{
			Username: "user",
			Password: "new_pass",
			Hostname: "addr:3306",
		},
	}

	// Run SetPassword in background so the test doesn't block on it
	doneChan := make(chan error, 1)
	go func() {
		doneChan <- ps.SetPassword(context.TODO(), creds)
		close(doneChan)
	}()

	// SetPassword should almost immediately start 2 goroutines which will block
	// in the mock SetPasswordFunc above
	time.Sleep(100 * time.Millisecond)

	mux.Lock()
	gotDbsRunning := dbsRunning
	mux.Unlock()
	if gotDbsRunning != 2 {
		t.Errorf("got %d dbs running in parallel, expected 2", gotDbsRunning)
	}

	// Unblock only 1 of the running dbs. This mean 1 of 2 is still blocked
	// and the 3rd starts, so still 2 running...
	unblockDb <- true
	time.Sleep(100 * time.Millisecond)
	mux.Lock()
	gotDbsRunning = dbsRunning
	mux.Unlock()
	if gotDbsRunning != 2 {
		t.Errorf("got %d dbs running in parallel, expected 2", gotDbsRunning)
	}

	// Unblock those two and the count should go to zero
	unblockDb <- true
	unblockDb <- true
	time.Sleep(100 * time.Millisecond)
	mux.Lock()
	gotDbsRunning = dbsRunning
	mux.Unlock()
	if gotDbsRunning != 0 {
		t.Errorf("got %d dbs running in parallel, expected 0", gotDbsRunning)
	}
}

func TestPasswordRollback(t *testing.T) {
	// Test that Rollback swaps creds.Current and creds.New so that previous
	// password sets with the creds are rolled back to the original password

	// Mock the RDS client to return data that simulates have only 1 RDS instance
	rdsClient := test.MockRDSClient{
		DescribeDBInstancesFunc: func(input *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []*rds.DBInstance{
					{
						DBInstanceArn:        aws.String("arn"),
						DBInstanceIdentifier: aws.String("db-1"),
						Endpoint: &rds.Endpoint{
							Address: aws.String("addr:3306"),
							Port:    aws.Int64(3306),
						},
					},
				},
			}, nil
		},
	}

	// Mock the PasswordClient so we don't have to use a real MySQL/RDS instance
	gotCreds := []db.NewPassword{}
	gotVerified := []db.NewPassword{}
	mysqlClient := test.MockMySQLPasswordClient{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotCreds = append(gotCreds, creds)
			return nil
		},
		VerifyPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotVerified = append(gotVerified, creds)
			return nil
		},
	}

	// Create new PasswordSetter with bare minimum config
	cfg := mysql.Config{
		RDSClient: rdsClient,
		DbClient:  mysqlClient,
	}
	ps := mysql.NewPasswordSetter(cfg)

	// Always need to call Init first
	secret := map[string]string{}
	err := ps.Init(context.TODO(), secret)
	if err != nil {
		t.Error(err)
	}

	// Normally, Rollback is called after SetPassword. And we only roll back passwords
	// the were set, so first we call SetPassword to mark them "set", then Rollback will
	// revert by swapping the creds
	creds := db.NewPassword{
		Current: db.Credentials{
			Username: "user",
			Password: "old_pass",
			Hostname: "addr:3306",
		},
		New: db.Credentials{
			Username: "user",
			Password: "new_pass",
			Hostname: "addr:3306",
		},
	}

	err = ps.SetPassword(context.TODO(), creds)
	if err != nil {
		t.Error(err)
	}

	err = ps.Rollback(context.TODO(), creds)
	if err != nil {
		t.Error(err)
	}

	expectCreds := []db.NewPassword{
		{ // SetPassword (old pass -> new)
			Current: db.Credentials{Username: "user", Password: "old_pass", Hostname: "addr:3306"},
			New:     db.Credentials{Username: "user", Password: "new_pass", Hostname: "addr:3306"},
		},
		{ // Rollback (new pass -> old)
			Current: db.Credentials{Username: "user", Password: "new_pass", Hostname: "addr:3306"}, // swapped
			New:     db.Credentials{Username: "user", Password: "old_pass", Hostname: "addr:3306"}, // swapped
		},
	}
	if diff := deep.Equal(gotCreds, expectCreds); diff != nil {
		t.Error(diff)
	}
}

func TestPasswordSetterNilEndpoint(t *testing.T) {
	// Test that Init doesn't panic when RDS API returns a db instance with
	// a nil Endpoint, which happens while the db is being provisioned
	rdsClient := test.MockRDSClient{
		DescribeDBInstancesFunc: func(input *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
			return &rds.DescribeDBInstancesOutput{
				DBInstances: []*rds.DBInstance{
					{
						DBInstanceArn:        aws.String("arn"),
						DBInstanceIdentifier: aws.String("db-1"),
						// nil Endpoint
					},
				},
			}, nil
		},
	}

	// Mock the PasswordClient so we don't have to use a real MySQL/RDS instance
	gotCreds := []db.NewPassword{}
	gotVerified := []db.NewPassword{}
	mysqlClient := test.MockMySQLPasswordClient{
		SetPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotCreds = append(gotCreds, creds)
			return nil
		},
		VerifyPasswordFunc: func(ctx context.Context, creds db.NewPassword) error {
			gotVerified = append(gotVerified, creds)
			return nil
		},
	}

	// Create new PasswordSetter with bare minimum config
	cfg := mysql.Config{
		RDSClient: rdsClient,
		DbClient:  mysqlClient,
	}
	ps := mysql.NewPasswordSetter(cfg)

	// If it does NOT handle nil Endpoint, this will panic
	err := ps.Init(context.TODO(), map[string]string{})
	if err != nil {
		t.Error(err)
	}
}
