// Copyright 2020, Square, Inc.

package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/square/password-rotation-lambda/v2/db"
)

// PasswordClient sets and verifies MySQL passwords. A PasswordSetter uses a
// Client to abstract away low-level MySQL communication.
//
// PasswordClient implementations must be safe for concurrent use by multiple goroutines.
type PasswordClient interface {
	SetPassword(ctx context.Context, creds db.NewPassword) error
	VerifyPassword(ctx context.Context, creds db.NewPassword) error
}

// RDSClient implements PasswordClient for RDS. It is safe for concurrent use by
// multiple goroutines. Retries are not supported. The caller is responsible for
// retrying on error.
//
// TLS connections using the 2019 RDS CA are supported. The RDS CA is built-in;
// it does not need to be provided.
type RDSClient struct {
	tls    bool
	dryrun bool
}

var _ PasswordClient = &RDSClient{}

// NewRDSClient creates a new RDSClient.
func NewRDSClient(useTLS, dryrun bool) *RDSClient {
	if useTLS {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(globalBundle)
		tlsConfig := &tls.Config{RootCAs: caCertPool}
		mysql.RegisterTLSConfig("rds", tlsConfig)
		log.Println("TLS enabled")
	}

	return &RDSClient{
		tls:    useTLS,
		dryrun: dryrun,
	}
}

// SetPassword connects as username on hostname and sets the password.
// Only the password for the given username is changed because the SQL query
// is "ALTER USER CURRENT_USER IDENTIFIED BY password".
//
// A new database connection is made on each call. If configured for a dry run,
// the connection is made but the SQL query is not executed.
func (c *RDSClient) SetPassword(ctx context.Context, creds db.NewPassword) error {
	// Connect with CURRENT credentials
	db, err := c.connect(ctx, creds.Current.Username, creds.Current.Password, creds.Current.Hostname)
	if err != nil {
		return err
	}
	defer db.Close()

	if c.dryrun {
		return nil
	}

	// Set NEW password
	escapedPassword := strings.ReplaceAll(creds.New.Password, "'", "\\'")
	alter := "ALTER USER CURRENT_USER IDENTIFIED BY '" + escapedPassword + "'"

	t0 := time.Now()
	_, err = db.ExecContext(ctx, alter)
	log.Printf("%s: exec response time: %dms", creds.Current.Hostname, time.Now().Sub(t0).Milliseconds())
	return err
}

// VerifyPassword connects as username on hostname with password. If the password
// is valid, the connection will be successful; else, an error is returned.
//
// A new database connection is made on each call. Dry run does not affect this function.
func (c *RDSClient) VerifyPassword(ctx context.Context, creds db.NewPassword) error {
	// Connect with NEW credentials
	db, err := c.connect(ctx, creds.New.Username, creds.New.Password, creds.New.Hostname)
	if db != nil {
		db.Close()
	}
	return err
}

// connect makes a DSN and connects to MySQL (RDS). This func is called by
// SetPassword and VerifyPassword.
func (c *RDSClient) connect(ctx context.Context, username, password, hostname string) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/", username, password, hostname)
	if c.tls {
		dsn += "?tls=rds"
	}

	// sql.Open() just creates a *sql.DB, it doesn't actually connect,
	// so we have to sql.Ping() to make a connectiion
	t0 := time.Now()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	log.Printf("%s: connect response time: %dms", hostname, time.Now().Sub(t0).Milliseconds())

	return db, nil
}
