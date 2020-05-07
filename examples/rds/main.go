package main

import (
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/secretsmanager"

	"github.com/square/rotate-password-lambda"
	"github.com/square/rotate-password-lambda/db/mysql"
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
