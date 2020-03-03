// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package fs implements a secret key store that
// stores secret keys as files on the file system.
package fs

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cache"
	"github.com/minio/kes/internal/secret"
)

// KeyStore is a file system secret key store
// that stores secret keys as files in a directory.
type KeyStore struct {
	// Dir is the directory where secret key files
	// are located. The key store will read / write
	// secrets from / to files in this directory.
	Dir string

	// CacheExpireAfter is the duration after which
	// cache entries expire such that they have to
	// be loaded from the backend storage again.
	CacheExpireAfter time.Duration

	// CacheExpireUnusedAfter is the duration after
	// which not recently used cache entries expire
	// such that they have to be loaded from the
	// backend storage again.
	// Not recently is defined as: CacheExpireUnusedAfter / 2
	CacheExpireUnusedAfter time.Duration

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	// Key is an optional key name of a cryptographic
	// key at the KMS. If the KMS is not nil the KeyStore
	// will try to encrypt secrets with this key at the KMS
	// before storing them at the filesystem.
	//
	// Therefore, Key must point to an existing key at
	// the key management system if KMS is set.
	Key string

	// KMS is an optional KMS client used to encrypt
	// secrets before storing them at the filesystem.
	// New secrets will be encrypted with the cryptographic
	// key referenced by Key.
	//
	// If not nil the KeyStore will reject any plaintext
	// secrets and only accept encrypted secrets.
	KMS secret.KMS

	cache cache.Cache
	once  uint32
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns kes.ErrKeyExists.
//
// In particular, Create creates a new file in KeyStore.Dir
// and writes the secret key to it.
func (store *KeyStore) Create(name string, secret secret.Secret) (err error) {
	store.initialize()
	if _, ok := store.cache.Get(name); ok {
		return kes.ErrKeyExists
	}

	var content io.WriterTo = secret
	if store.KMS != nil {
		content, err = store.KMS.Encrypt(store.Key, secret)
		if err != nil {
			store.logf("fs: failed to encrypt secret '%s' with master key '%s': %v", name, store.Key, err)
			return err
		}
	}

	path := filepath.Join(store.Dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil && os.IsExist(err) {
		return kes.ErrKeyExists
	}
	if err != nil {
		store.logf("fs: cannot open %s: %v", path, err)
		return err
	}
	defer file.Close()

	if _, err = content.WriteTo(file); err != nil {
		if rmErr := os.Remove(path); rmErr != nil {
			store.logf("fs: cannot remove %s: %v", path, err)
		}
		return err
	}

	if err = file.Sync(); err != nil { // Ensure that we wrote the secret key to disk
		store.logf("fs: cannot to flush and sync %s: %v", path, err)
		if rmErr := os.Remove(path); rmErr != nil {
			store.logf("fs: cannot remove %s: %v", path, err)
		}
		return err
	}
	store.cache.Set(name, secret)
	return nil
}

// Get returns the secret key associated with the given name.
// If no entry for name exists, Get returns kes.ErrKeyNotFound.
//
// In particular, Get reads the secret key from the associated
// file in KeyStore.Dir.
func (store *KeyStore) Get(name string) (secret.Secret, error) {
	store.initialize()
	if secret, ok := store.cache.Get(name); ok {
		return secret, nil
	}

	// Since we haven't found the requested secret key in the cache
	// we reach out to the disk to fetch it from there.
	path := filepath.Join(store.Dir, name)
	file, err := os.Open(path)
	if err != nil && os.IsNotExist(err) {
		return secret.Secret{}, kes.ErrKeyNotFound
	}
	if err != nil {
		store.logf("fs: cannot open '%s': %v", path, err)
		return secret.Secret{}, err
	}
	defer file.Close()

	var sec secret.Secret
	if store.KMS == nil {
		if _, err := sec.ReadFrom(file); err != nil {
			store.logf("fs: failed to parse secret at '%s': %v", path, err)
			return sec, err
		}
	} else {
		var ciphertext secret.Ciphertext
		if _, err := ciphertext.ReadFrom(file); err != nil {
			store.logf("fs: failed to parse ciphertext at '%s': %v", path, err)
			return sec, kes.ErrKeySealed
		}
		sec, err := store.KMS.Decrypt(ciphertext)
		if err != nil {
			store.logf("fs: failed to decrypt ciphertext at '%s': %v", path, err)
			return sec, kes.ErrKeySealed
		}
	}

	secret, _ := store.cache.Add(name, sec)
	return secret, nil
}

// Delete removes a the secret key with the given name
// from the key store and deletes the associated file,
// if it exists.
func (store *KeyStore) Delete(name string) error {
	path := filepath.Join(store.Dir, name)
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		err = nil // Ignore the error if the file does not exist
	}
	store.cache.Delete(name)
	if err != nil {
		store.logf("fs: failed to delete '%s': %v", path, err)
	}
	return err
}

func (store *KeyStore) initialize() {
	if atomic.CompareAndSwapUint32(&store.once, 0, 1) {
		store.cache.StartGC(context.Background(), store.CacheExpireAfter)
		store.cache.StartUnusedGC(context.Background(), store.CacheExpireUnusedAfter/2)
	}
}

func (store *KeyStore) logf(format string, v ...interface{}) {
	if store.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		store.ErrorLog.Printf(format, v...)
	}
}
