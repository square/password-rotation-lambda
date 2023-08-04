// Copyright 2020, Square, Inc.

package mysql

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/rds/rdsiface"

	"github.com/square/password-rotation-lambda/v2/db"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile | log.LUTC)
}

// Config configures a PasswordSetter when passed to NewPasswordSetter.
type Config struct {
	RDSClient rdsiface.RDSAPI
	DbClient  PasswordClient
	Filter    func(*rds.DBInstance) bool
	Parallel  uint
	Retry     uint
	RetryWait time.Duration
}

// PasswordSetter implements the db.PasswordSetter interface for RDS.
type PasswordSetter struct {
	cfg Config
	// --
	initDone    bool
	tries       uint
	maxParallel chan bool
	dbs         []dbInstance
}

var _ db.PasswordSetter = &PasswordSetter{}

// dbInstance is used by PasswordSetter to track work done on an RDS instance
// (the bool vars) and if the work was successful (the error vars).
type dbInstance struct {
	hostname      string
	set           bool
	verified      bool
	rolledBack    bool
	setError      error
	verifyError   error
	rollbackError error
}

// NewPasswordSetter creates a new PasswordSetter.
func NewPasswordSetter(cfg Config) *PasswordSetter {
	if cfg.Parallel == 0 {
		cfg.Parallel = 1
	}
	maxParallel := make(chan bool, cfg.Parallel)
	for i := uint(0); i < cfg.Parallel; i++ {
		maxParallel <- true
	}
	return &PasswordSetter{
		cfg: cfg,
		// --
		tries:       uint(1) + cfg.Retry,
		maxParallel: maxParallel,
	}
}

// Init calls RDS DescribeDBInstances to get all RDS instances. The user-provided
// filter func is called to filter out instances. The final list of instances is
// cached so RDS DescribeDBInstances is called only once.
func (m *PasswordSetter) Init(ctx context.Context, secret map[string]string) error {
	t0 := time.Now()
	log.Println("Init call")
	defer func() {
		d := time.Now().Sub(t0)
		log.Printf("Init return: %dms", d.Milliseconds())
	}()

	// Rotator calls this func on every step, but only get the dbs once for two
	// reasons. First, reduce AWS API calls and save money. Second, the list of
	// dbs can change between calls (steps) which doesn't work. E.g. if a new db
	// is provisioned after rotate step 2, we don't want to do only steps 3 and
	// 4 on it. So rotation should happen on a point-in-time snapshot of the dbs.
	if m.initDone {
		return nil
	}

	// Query AWS RDS API to get list of all RDS instances
	t1 := time.Now()
	input := &rds.DescribeDBInstancesInput{} // all instances
	result, err := m.cfg.RDSClient.DescribeDBInstances(input)
	log.Printf("RDS.DescribeDBInstances response time: %dms", time.Now().Sub(t1).Milliseconds())
	if err != nil {
		return err
	}

	// Call user-provided filter func to filter out db instances. The log line
	// is so the entire list of db instances appears as one log line in CloudWatch
	// console, i.e. keeping it together makes it easier to see.
	line := fmt.Sprintf("RDS instances:")
	dbs := []dbInstance{}
	for _, rds := range result.DBInstances {

		// When a db is being created, AWS returns most info but *Endpoint is nil
		if rds.Endpoint == nil || rds.Endpoint.Address == nil {
			dbId := aws.StringValue(rds.DBInstanceIdentifier) // aws.String() doesn't check for nil
			log.Printf("%s has no endpoint address, skipping (database instance is being provisioned or decommissioned)", dbId)
			continue
		}

		// Filter out (skip) this db instance?
		if m.cfg.Filter != nil && m.cfg.Filter(rds) {
			line += fmt.Sprintf("\t%s (filtered out)\n", *rds.Endpoint.Address)
			continue
		}

		// Save db instance; include in password rotations
		dbs = append(dbs, dbInstance{hostname: *rds.Endpoint.Address})
		line += fmt.Sprintf(" %s", *rds.Endpoint.Address)
	}
	log.Print(line)

	m.dbs = dbs
	m.initDone = true
	return nil
}

// SetPassword sets the password on all RDS instances.
func (m *PasswordSetter) SetPassword(ctx context.Context, creds db.NewPassword) error {
	t0 := time.Now()
	log.Println("SetPassword call")
	defer func() {
		d := time.Now().Sub(t0)
		log.Printf("SetPassword return: %dms", d.Milliseconds())
	}()

	// Reset flags and errors between attempts to set the password. If this
	// isn't done and run 1 fails but run 2 succeeds, it'll cause a false-positive
	// return error from setAll because in run 2 it'll see the error from run 1.
	for i, db := range m.dbs {
		m.dbs[i] = dbInstance{hostname: db.hostname}
	}

	return m.setAll(ctx, creds, set_password)
}

// Rollback sets the password on all RDS instances. For this implementation, it
// is identical to SetPassword.
func (m *PasswordSetter) Rollback(ctx context.Context, creds db.NewPassword) error {
	t0 := time.Now()
	log.Println("Rollback call")
	defer func() {
		d := time.Now().Sub(t0)
		log.Printf("Rollback return: %dms", d.Milliseconds())
	}()
	swapCreds := db.NewPassword{
		Current: creds.New,
		New:     creds.Current,
	}
	return m.setAll(ctx, swapCreds, rollback_password) // true = setting
}

// VerifyPassword connects to all RDS to verify that the username and password work.
func (m *PasswordSetter) VerifyPassword(ctx context.Context, creds db.NewPassword) error {
	t0 := time.Now()
	log.Println("VerifyPassword call")
	defer func() {
		d := time.Now().Sub(t0)
		log.Printf("VerifyPassword return: %dms", d.Milliseconds())
	}()
	return m.setAll(ctx, creds, verify_password)
}

// --------------------------------------------------------------------------

const (
	set_password      = "setting"
	verify_password   = "verify"
	rollback_password = "rollback"
)

// setAll sets or verifies the password on all databases in parallel. It waits
// for all to complete, even after the context is cancelled to let the in-flight
// database calls complete (which are also watching the context, so they should
// not block).
//
// A successful run happens when all databases are set or verified without error.
// Else, any failure causes an error return.
//
// This func is called by SetPassword and Rollback.
func (m *PasswordSetter) setAll(ctx context.Context, creds db.NewPassword, action string) error {
	log.Printf("%s password on %d RDS instances, %d in parallel...", action, len(m.dbs), m.cfg.Parallel)
	var wg sync.WaitGroup
	for i := range m.dbs {
		// Wait for a slot in the parallel semaphore or the context to be cancelled
		select {
		case <-m.maxParallel:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}

		if action == rollback_password && !m.dbs[i].set {
			log.Printf("%s: new password was not set, skip rollback", m.dbs[i].hostname)
			// Sending to maxParallel so that we don't wait indefinitely
			// for maxParallel channel in the rollback path.
			m.maxParallel <- true
			continue
		}

		// Change password on one database
		wg.Add(1)
		go func(dbNo int, creds db.NewPassword) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("%s: PANIC: %v", m.dbs[dbNo].hostname, r)
				}
				m.maxParallel <- true
				wg.Done()
			}()

			// creds is a copy, not a pointer, so this only modifies our local copy.
			// Higher callers don't use Hostname, but we need to plumb it down to the
			// PasswordSetter which uses it.
			creds.Current.Hostname = m.dbs[dbNo].hostname
			creds.New.Hostname = m.dbs[dbNo].hostname

			// --------------------------------------------------------------
			// Try to set/verify/rollback MySQL user password
			if err := m.setOne(ctx, creds, action); err != nil {
				log.Printf("ERROR: %s: %s password failed: %s", m.dbs[dbNo].hostname, action, err)

				switch action {
				case set_password:
					m.dbs[dbNo].setError = err
				case verify_password:
					m.dbs[dbNo].verifyError = err
				case rollback_password:
					m.dbs[dbNo].rollbackError = err
				default:
					panic("invalid action passed to setAll: " + action)
				}

				return // Failed to set/verify/rollback
			}

			// Success, mark that set/verify/rollback was ok
			log.Printf("%s: success %s password", m.dbs[dbNo].hostname, action)
			switch action {
			case set_password:
				m.dbs[dbNo].set = true
			case verify_password:
				m.dbs[dbNo].verified = true
			case rollback_password:
				m.dbs[dbNo].rolledBack = true
			default:
				panic("invalid action passed to setAll: " + action)
			}
		}(i, creds)
	}

	// Wait for all the in-flight setOne goroutines to finish
	log.Printf("waiting for %s password on %d RDS instances...", action, len(m.dbs))
	wg.Wait()

	// Return error if any database failed to set
	errCount := 0
	for _, db := range m.dbs {
		switch action {
		case set_password:
			if db.setError != nil {
				errCount += 1
			}
		case verify_password:
			if db.verifyError != nil {
				errCount += 1
			}
		case rollback_password:
			if db.rollbackError != nil {
				errCount += 1
			}
		}
	}
	if errCount > 0 {
		return fmt.Errorf("%s failed on %d database instances, see previous log output", action, errCount)
	}

	return nil
}

// setOne sets or verifies the password on one database. On error, it waits and
// retries as configured.
//
// This func is called as a goroutine from setAll.
func (m *PasswordSetter) setOne(ctx context.Context, creds db.NewPassword, action string) error {
	for tryNo := uint(1); tryNo <= m.tries; tryNo++ {
		// Do the low-level password change on the database
		var err error
		if action == verify_password {
			err = m.cfg.DbClient.VerifyPassword(ctx, creds)
		} else {
			err = m.cfg.DbClient.SetPassword(ctx, creds)
		}
		if err == nil { // early return on success
			return nil
		}

		// ------------------------------------------------------------------
		// Error, retry?
		if tryNo == m.tries { // early return on last try (don't sleep)
			return err
		}

		// Error setting password and retries remain...

		// Check context before sleeping. If it was canceled during the
		// SetPassword call, we need to return immediately. Return the
		// SetPassword err because  that's the last thing we ran.
		select {
		case <-ctx.Done():
			log.Printf("%s: context cancelled after %s password, not retrying (%d tries remained)", creds.Current.Hostname, action, m.tries-tryNo)
			return err
		default:
		}

		// Sleep between tries
		log.Printf("%s: error %s password try %d of %d, retry in %s: %s", creds.Current.Hostname, action, tryNo, m.tries, m.cfg.RetryWait, err)
		time.Sleep(m.cfg.RetryWait)

		// Check context again in case it was cancelled during the sleep. Return
		// the context error because we'd only return here if it's cancelled;
		// returning the SetPassword err here would be misleading.
		select {
		case <-ctx.Done():
			log.Printf("%s: context cancelled after %s password retry wait, not retrying (%d tries remained)", creds.Current.Hostname, action, m.tries-tryNo)
			return ctx.Err()
		default:
		}
	}

	// Code shouldn't reach here. Don't panic (caller doesn't recover), just return an error.
	return fmt.Errorf("mysql.PasswordSetter.setOne() reached end of function on %s password", action)
}
