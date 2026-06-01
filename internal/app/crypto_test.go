// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	plaintext := []byte("github 6 JBSWY3DP\ngitlab 6 GEZDGNBVGY3TQOJQ\n")
	passphrase := "test-passphrase-123"

	encrypted, err := encryptData(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}
	if !bytes.HasPrefix(encrypted, []byte(magicHeader)) {
		t.Error("encrypted data missing magic header")
	}
	decrypted, err := decryptData(encrypted, passphrase)
	if err != nil {
		t.Fatalf("decryptData: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecrypt_WrongPassphrase(t *testing.T) {
	plaintext := []byte("github 6 JBSWY3DP\n")
	encrypted, err := encryptData(plaintext, "correct-passphrase")
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}
	_, err = decryptData(encrypted, "wrong-passphrase")
	if err == nil {
		t.Error("expected error for wrong passphrase")
	}
}

func TestDecrypt_NoMagicHeader(t *testing.T) {
	_, err := decryptData([]byte("no header here\n"), "pass")
	if err == nil {
		t.Error("expected error for missing magic header")
	}
}

func TestEncrypt_UniqueCiphertexts(t *testing.T) {
	plaintext := []byte("test 6 JBSWY3DP\n")
	pass := "test-pass"

	encrypted1, err := encryptData(plaintext, pass)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}
	decrypted, err := decryptData(encrypted1, pass)
	if err != nil {
		t.Fatalf("decryptData: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypt round-trip failed")
	}

	encrypted2, err := encryptData(plaintext, pass)
	if err != nil {
		t.Fatalf("encryptData second time: %v", err)
	}
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("two encryptions should produce different ciphertext")
	}
	decrypted2, err := decryptData(encrypted2, pass)
	if err != nil {
		t.Fatalf("decryptData second encrypt: %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("second decrypt round-trip failed")
	}
}
