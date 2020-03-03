// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"bytes"
	"strings"
	"testing"
)

var ciphertextStringTests = []struct {
	Ciphertext Ciphertext
	String     string
}{
	{ // 0
		Ciphertext: Ciphertext{},
		String:     `{"key":"","bytes":""}`,
	},
	{ // 1
		Ciphertext: Ciphertext{Key: "my-key"},
		String:     `{"key":"my-key","bytes":""}`,
	},
	{ // 2
		Ciphertext: Ciphertext{Key: "my-key", Bytes: make([]byte, 16)},
		String:     `{"key":"my-key","bytes":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
	},
	{ // 3
		Ciphertext: Ciphertext{Key: "my-key", Bytes: mustDecodeHex("5b647be0a1ecb2a01d3b0223f19b454b114be28cda1bf55bd28c478980139986")},
		String:     `{"key":"my-key","bytes":"W2R74KHssqAdOwIj8ZtFSxFL4ozaG/Vb0oxHiYATmYY="}`,
	},
}

func TestCiphertextString(t *testing.T) {
	for i, test := range ciphertextStringTests {
		if s := test.Ciphertext.String(); s != test.String {
			t.Fatalf("Test %d: got %s - want %s", i, s, test.String)
		}
	}
}

func TestCiphertextWriteTo(t *testing.T) {
	for i, test := range ciphertextStringTests {
		var sb strings.Builder
		test.Ciphertext.WriteTo(&sb)
		if s := sb.String(); s != test.String {
			t.Fatalf("Test %d: got %s - want %s", i, s, test.String)
		}
	}
}

var ciphertextReadFromTests = []struct {
	Ciphertext Ciphertext
	String     string
	ShouldFail bool
}{
	{ // 0
		Ciphertext: Ciphertext{Key: " "},
		String:     `{"key":" ","bytes":""}`,
	},
	{ // 1
		Ciphertext: Ciphertext{Key: "my-key"},
		String:     `{"key":"my-key", "bytes":""}`,
	},
	{ // 2
		Ciphertext: Ciphertext{Key: "my-key", Bytes: make([]byte, 16)},
		String:     `{"key":"my-key", "bytes":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
	},
	{ // 3
		Ciphertext: Ciphertext{Key: "some-key", Bytes: mustDecodeHex("27caa63b2115d9c7b6ca8002fb9b7463b0923ff853329a4bed71e9027c9cfb41")},
		String:     `{"key":"some-key","bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="}`,
	},

	{ // 4
		Ciphertext: Ciphertext{},
		String:     `{}`, // The key must not be empty
		ShouldFail: true,
	},
	{ // 5
		Ciphertext: Ciphertext{Key: ""},
		String:     `{"key":""}`, // The key must not be empty
		ShouldFail: true,
	},
	{ // 6
		Ciphertext: Ciphertext{},
		String:     `{"key-2":""}`,
		ShouldFail: true, // "key-2" is a unknown field
	},
	{ // 7
		Ciphertext: Ciphertext{},
		String:     `{"key":"}`,
		ShouldFail: true, // invalid JSON
	},
	{ // 8
		Ciphertext: Ciphertext{Key: "some-key", Bytes: mustDecodeHex("27caa63b2115d9c7b6ca8002fb9b7463b0923ff853329a4bed71e9027c9cfb41")},
		String:     `{"key":"some-key","bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0="}`,
		ShouldFail: true, // invalid base64
	},
}

func TestCiphertextReadFrom(t *testing.T) {
	for i, test := range ciphertextReadFromTests {
		var ciphertext Ciphertext
		n, err := ciphertext.ReadFrom(strings.NewReader(test.String))
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to read from string: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: ReadFrom should have failed bit it succeeded", i)
		}
		if err == nil {
			if n != int64(len(test.String)) {
				t.Fatalf("Test %d: ReadFrom returns incorrect number of bytes:  got %d - want %d", i, n, int64(len(test.String)))
			}
			if ciphertext.Key != test.Ciphertext.Key {
				t.Fatalf("Test %d: invalid key: got %s - want %s", i, ciphertext.Key, test.Ciphertext.Key)
			}
			if !bytes.Equal(ciphertext.Bytes, test.Ciphertext.Bytes) {
				t.Fatalf("Test %d: invalid ciphertext: got %x - want %x", i, ciphertext.Bytes, test.Ciphertext.Bytes)
			}
		}
	}
}
