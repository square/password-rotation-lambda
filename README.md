# Password Rotation Lambda

`password-rotation-lambda` is an [AWS Lambda](https://aws.amazon.com/lambda/)
function (in Go) that rotates database passwords using [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/).
Currently, it supports RDS for MySQL.

This package handles the four Secrets Manager rotation steps and database-specific
password setting. Currently, it only supports RDS for MySQL. Your `main.go` imports
this packages (which exports itself as `rotate` for short) and provides
AWS sessions/clients and a `SecretSetter` to decode your secret string.

```go
package main

import (
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/square/password-rotation-lambda"
	"github.com/square/password-rotation-lambda/db/mysql"
)

func main() {
	// Start AWS session using env vars automatically set by Lambda
	sess, err := session.NewSession()
	if err != nil {
		log.Fatalf("error making AWS session: %s", err)
	}

	// Make password setter for MySQL (RDS)
	ps := mysql.NewPasswordSetter(mysql.Config{
		RDSClient: rds.New(sess),                   // RDS API client
		DbClient:  mysql.NewRDSClient(true, false), // RDS MySQL cilent (true=TLS, false=dry run)
	})

	// Make Rotator which is the Lambda function/handler
	r := rotate.NewRotator(rotate.Config{
		SecretsManager: secretsmanager.New(sess),
		PasswordSetter: ps,
	})

	// Run Rotator in Lambda, waiting for events from Secrets Manager
	lambda.Start(r.Handler)
}

```

More docs and examples to come.
