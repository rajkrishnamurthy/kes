// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package mem implements an in-memory secret key store.
package mem

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cache"
	"github.com/minio/kes/internal/secret"
)

// KeyStore is an in-memory secret key store.
type KeyStore struct {
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
	// before storing them in its in-memory store.
	//
	// Therefore, Key must point to an existing key at
	// the key management system if KMS is set.
	Key string

	// KMS is an optional KMS client used to encrypt
	// secrets before storing them in its in-memory store.
	// New secrets will be encrypted with the cryptographic
	// key referenced by Key.
	//
	// If not nil the KeyStore will reject any plaintext
	// secrets and only accept encrypted secrets.
	KMS secret.KMS

	cache cache.Cache

	lock  sync.RWMutex
	store map[string]string

	once sync.Once // initializes the store and starts cache GCs
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns kes.ErrKeyExists.
func (store *KeyStore) Create(name string, secret secret.Secret) (err error) {
	store.lock.Lock()
	defer store.lock.Unlock()

	if _, ok := store.cache.Get(name); ok {
		return kes.ErrKeyExists
	}
	if store.store == nil {
		store.once.Do(store.initialize)
	}

	var content fmt.Stringer = secret
	if store.KMS != nil {
		content, err = store.KMS.Encrypt(store.Key, secret)
		if err != nil {
			store.logf("mem: failed to encrypt secret '%s' with master key '%s': %v", name, store.Key, err)
			return err
		}
	}

	if _, ok := store.store[name]; ok {
		return kes.ErrKeyExists
	}
	store.cache.Set(name, secret)
	store.store[name] = content.String()
	return nil
}

// Delete removes a the secret key with the given name
// from the key store if it exists.
func (store *KeyStore) Delete(name string) error {
	store.lock.Lock()
	store.cache.Delete(name)
	delete(store.store, name)
	store.lock.Unlock()
	return nil
}

// Get returns the secret key associated with the given name.
// If no entry for name exists, Get returns kes.ErrKeyNotFound.
func (store *KeyStore) Get(name string) (secret.Secret, error) {
	sec, ok := store.cache.Get(name)
	if ok {
		return sec, nil
	}

	// The secret key is not in the cache.
	// So we check whether it exists at all
	// and, if so, add it to the cache.
	store.lock.Lock()
	defer store.lock.Unlock()

	s, ok := store.store[name]
	if !ok {
		return secret.Secret{}, kes.ErrKeyNotFound
	}

	var err error
	if store.KMS == nil {
		if err = sec.ParseString(s); err != nil {
			store.logf("mem: failed to parse secret '%s': %v", name, err)
			return secret.Secret{}, err
		}
	} else {
		var ciphertext secret.Ciphertext
		if _, err = ciphertext.ReadFrom(strings.NewReader(s)); err != nil {
			store.logf("mem: failed to parse ciphertext '%s': %v", name, err)
			return secret.Secret{}, kes.ErrKeySealed
		}
		sec, err = store.KMS.Decrypt(ciphertext)
		if err != nil {
			store.logf("mem: failed to decrypt ciphertext '%s': %v", name, err)
			return secret.Secret{}, kes.ErrKeySealed
		}
	}
	store.cache.Set(name, sec)
	return sec, nil
}

func (store *KeyStore) initialize() {
	// We have to hold the write-lock here
	// since once.Do may modify the in-memory
	// store.
	if store.store == nil {
		store.store = map[string]string{}
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
