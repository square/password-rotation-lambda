// Copyright 2020, Square, Inc.

package test

import (
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/rds/rdsiface"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

type MockSecretsManager struct {
	secretsmanageriface.SecretsManagerAPI
	GetSecretValueFunc           func(*secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValueFunc           func(*secretsmanager.PutSecretValueInput) (*secretsmanager.PutSecretValueOutput, error)
	UpdateSecretVersionStageFunc func(*secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error)
}

func (m MockSecretsManager) GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	if m.GetSecretValueFunc != nil {
		return m.GetSecretValueFunc(input)
	}
	return nil, nil
}

func (m MockSecretsManager) PutSecretValue(input *secretsmanager.PutSecretValueInput) (*secretsmanager.PutSecretValueOutput, error) {
	if m.PutSecretValueFunc != nil {
		return m.PutSecretValueFunc(input)
	}
	return nil, nil
}

func (m MockSecretsManager) UpdateSecretVersionStage(input *secretsmanager.UpdateSecretVersionStageInput) (*secretsmanager.UpdateSecretVersionStageOutput, error) {
	if m.UpdateSecretVersionStageFunc != nil {
		return m.UpdateSecretVersionStageFunc(input)
	}
	return nil, nil
}

// --------------------------------------------------------------------------

type MockRDSClient struct {
	rdsiface.RDSAPI
	DescribeDBInstancesFunc func(*rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error)
}

func (m MockRDSClient) DescribeDBInstances(input *rds.DescribeDBInstancesInput) (*rds.DescribeDBInstancesOutput, error) {
	if m.DescribeDBInstancesFunc != nil {
		return m.DescribeDBInstancesFunc(input)
	}
	return nil, nil
}
