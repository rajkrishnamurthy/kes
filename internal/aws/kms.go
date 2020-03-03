// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package aws

import (
	"bytes"
	"log"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	awskms "github.com/aws/aws-sdk-go/service/kms"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/secret"
)

// KMS is an AWS-KMS client that implements
// the secret.KMS interface.
//
// It can be used to encrypt secrets before
// storing them at a key store resp. decrypt
// them after fetching them from such a store.
type KMS struct {
	// Addr is the HTTP address of the AWS KMS.
	// In general, the address has the following
	// form:
	//  kms.<region>.amazonaws.com
	Addr string

	// Region is the AWS region. Even though the Addr
	// endpoint contains that information already, this
	// field is mandatory.
	Region string

	// Login contains the AWS credentials (access/secret key).
	Login Credentials

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	client *awskms.KMS
}

var _ secret.KMS = (*KMS)(nil)

// Authenticate tries to establish a connection to
// the AWS KMS using the login credentials.
func (kms *KMS) Authenticate() error {
	credentials := credentials.NewStaticCredentials(
		kms.Login.AccessKey,
		kms.Login.SecretKey,
		kms.Login.SessionToken,
	)
	if kms.Login.AccessKey == "" && kms.Login.SecretKey == "" && kms.Login.SessionToken == "" {
		// If all login credentials (access key, secret key and session token) are empty
		// we pass no (not empty) credentials to the AWS SDK. The SDK will try to fetch
		// the credentials from:
		//  - Environment Variables
		//  - Shared Credentials file
		//  - EC2 Instance Metadata
		// In particular, when running a kes server on an EC2 instance, the SDK will
		// automatically fetch the temp. credentials from the EC2 metadata service.
		// See: AWS IAM roles for EC2 instances.
		credentials = nil
	}

	session, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Endpoint:    aws.String(kms.Addr),
			Region:      aws.String(kms.Region),
			Credentials: credentials,
		},
		SharedConfigState: session.SharedConfigDisable,
	})
	if err != nil {
		return err
	}
	kms.client = awskms.New(session)
	return nil
}

// Encrypt tries to encrypt the given plaintext with the specified
// CMK at the AWS-KMS instance. It returns the encrypted plaintext
// as ciphertext.
func (kms *KMS) Encrypt(key string, plaintext secret.Secret) (secret.Ciphertext, error) {
	ciphertext, err := kms.client.Encrypt(&awskms.EncryptInput{
		KeyId:     aws.String(key),
		Plaintext: []byte(plaintext.String()),
	})
	if err != nil {
		if err, ok := err.(awserr.Error); ok {
			switch err.Code() {
			case awskms.ErrCodeNotFoundException:
				kms.logf("aws: the CMK '%s' does not exist: %v", key, err)
			case awskms.ErrCodeDisabledException:
				kms.logf("aws: the CMK '%s' is disabled: %v", key, err)
			case awskms.ErrCodeKeyUnavailableException:
				kms.logf("aws: the CMK '%s' is not available: %v", key, err)
			case awskms.ErrCodeInvalidKeyUsageException:
				kms.logf("aws: the CMK '%s' cannot be used for encryption: %v", key, err)
			case awskms.ErrCodeInvalidStateException:
				kms.logf("aws: the CMK '%s' is in an invalid state: %v", key, err)
			default:
				kms.logf("aws: %v", err)
			}
		} else {
			kms.logf("aws: %v", err)
		}
		return secret.Ciphertext{}, kes.NewError(http.StatusInternalServerError, "cannot encrypt key")
	}
	return secret.Ciphertext{
		Key:   *ciphertext.KeyId,
		Bytes: ciphertext.CiphertextBlob,
	}, nil
}

// Decrypt tries to decrypt the given ciphertext with the AWS-KMS.
// It returns the plaintext secret on success.
func (kms *KMS) Decrypt(ciphertext secret.Ciphertext) (secret.Secret, error) {
	plaintext, err := kms.client.Decrypt(&awskms.DecryptInput{
		KeyId:          aws.String(ciphertext.Key),
		CiphertextBlob: ciphertext.Bytes,
	})
	if err != nil {
		if err, ok := err.(awserr.Error); ok {
			switch err.Code() {
			case awskms.ErrCodeNotFoundException:
				kms.logf("aws: the CMK '%s' does not exist", ciphertext.Key)
			case awskms.ErrCodeDisabledException:
				kms.logf("aws: the CMK '%s' is disabled", ciphertext.Key)
			case awskms.ErrCodeInvalidCiphertextException:
				kms.logf("aws: secret is not authentic: %v", err)
			case awskms.ErrCodeIncorrectKeyException:
				kms.logf("aws: secret was not encrypted with '%s'", ciphertext.Key)
			case awskms.ErrCodeKeyUnavailableException:
				kms.logf("aws: the CMK '%s' is not available", ciphertext.Key)
			case awskms.ErrCodeInvalidKeyUsageException:
				kms.logf("aws: the CMK '%s' cannot be used for decryption", ciphertext.Key)
			case awskms.ErrCodeInvalidStateException:
				kms.logf("aws: the CMK '%s' is in an invalid state", ciphertext.Key)
			default:
				kms.logf("aws: %v", err)
			}
		} else {
			kms.logf("aws: %v", err)
		}
		return secret.Secret{}, kes.ErrKeySealed
	}
	var secret secret.Secret
	if _, err = secret.ReadFrom(bytes.NewReader(plaintext.Plaintext)); err != nil {
		return secret, err
	}
	return secret, nil
}

func (kms *KMS) logf(format string, v ...interface{}) {
	if kms.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		kms.ErrorLog.Printf(format, v...)
	}
}
