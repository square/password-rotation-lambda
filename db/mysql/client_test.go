// Copyright 2020, Square, Inc.

package mysql_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	rdb "github.com/square/password-rotation-lambda/v2/db"
	"github.com/square/password-rotation-lambda/v2/db/mysql"
)

var (
	default_dsn = "root@tcp(127.0.0.1:3306)/"
	user        = "square_test"
	host        = "127.0.0.1"
	pass        = "password"
)

func setup(t *testing.T) (*sql.DB, error) {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		dsn = default_dsn
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	queries := []string{
		fmt.Sprintf("DROP USER IF EXISTS '%s'@'%s'", user, host),
		fmt.Sprintf("CREATE USER '%s'@'%s' IDENTIFIED BY '%s'", user, host, pass),
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}

func TestClient(t *testing.T) {
	db, err := setup(t)
	if err != nil {
		t.Skip(err)
	}

	defer db.Close()

	client := mysql.NewRDSClient(false, false)

	creds := rdb.NewPassword{
		Current: rdb.Credentials{
			Username: user,
			Password: pass,
			Hostname: host,
		},
		New: rdb.Credentials{
			Username: user,
			Password: "newpass",
			Hostname: host,
		},
	}

	err = client.SetPassword(context.TODO(), creds)
	if err != nil {
		t.Error(err)
	}

	err = client.VerifyPassword(context.TODO(), creds)
	if err != nil {
		t.Error(err)
	}
}
