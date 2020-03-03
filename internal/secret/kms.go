// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// KMS is a key management system that holds a set
// of cryptographic secret keys. The KMS interface
// specifies what operations can be performed with
// these secret keys.
//
// In particularly, a KMS can encrypt a value, i.e.
// a secret, with one of its cryptographic keys and
// return a ciphertext.
// The ciphertext can then be passed to the KMS - which
// decrypts it and returns the plaintext.
type KMS interface {
	// Encrypt encrypts the given plaintext with the
	// cryptographic key referenced by the given key name.
	// It returns the encrypted plaintext as ciphertext.
	Encrypt(key string, plaintext Secret) (Ciphertext, error)

	// Decrypt tries to decrypt the given ciphertext
	// and returns the secret plaintext on success.
	Decrypt(ciphertext Ciphertext) (Secret, error)
}

// Ciphertext represents a Secret encrypted with a
// cryptographic key using a KMS.
//
// A valid Ciphertext must contain a non-empty key.
type Ciphertext struct {
	Key   string `json:"key"`   // The name of the key at the KMS - must not me empty
	Bytes []byte `json:"bytes"` // The encrypted secret
}

// String returns the string representation
// of the ciphertext.
//
// It is guaranteed that the returned string
// is valid JSON.
func (c Ciphertext) String() string {
	return fmt.Sprintf(`{"key":"%s","bytes":"%s"}`, c.Key, base64.StdEncoding.EncodeToString(c.Bytes))
}

// WriteTo writes the string representation of the
// ciphertext to w. It returns the first error
// encountered during writing, if any, and the number
// of bytes written to w.
func (c Ciphertext) WriteTo(w io.Writer) (int64, error) {
	n, err := io.WriteString(w, c.String())
	return int64(n), err
}

// ReadFrom tries to read a well-formed ciphertext
// form r. It returns the first error encountered
// during reading, if any, and the number of bytes
// read from r.
func (c *Ciphertext) ReadFrom(r io.Reader) (int64, error) {
	const MaxSize = 10 * 1 << 20 // max 10 MiB
	R := &io.LimitedReader{R: r, N: MaxSize}

	decoder := json.NewDecoder(R)
	decoder.DisallowUnknownFields()

	var err error
	if err = decoder.Decode(c); err != nil {
		err = errors.New("ciphertext is malformed")
	}
	switch n := MaxSize - R.N; {
	case err != nil:
		return n, err
	case c.Key == "":
		return n, errors.New("ciphertext is malformed")
	default:
		return n, nil
	}
}
