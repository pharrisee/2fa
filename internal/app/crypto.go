// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

func deriveKey(passphrase string, salt []byte) []byte {
	if cachedKey != nil {
		return cachedKey
	}
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, aesKeyLen)
	cachedKey = key
	return key
}

func encryptData(plaintext []byte, passphrase string) ([]byte, error) {
	// Clear cached key since encryption uses a fresh salt each time.
	cachedKey = nil
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	payload := make([]byte, 0, saltLen+nonceLen+len(ciphertext))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	encoded := make([]byte, 0, len(magicHeader)+base64.StdEncoding.EncodedLen(len(payload))+1)
	encoded = append(encoded, []byte(magicHeader)...)
	encoded = append(encoded, []byte(base64.StdEncoding.EncodeToString(payload))...)
	encoded = append(encoded, '\n')
	return encoded, nil
}

func decryptData(raw []byte, passphrase string) ([]byte, error) {
	payload, ok := bytes.CutPrefix(raw, []byte(magicHeader))
	if !ok {
		return nil, fmt.Errorf("missing magic header")
	}
	payload = bytes.TrimSpace(payload)

	decoded, err := base64.StdEncoding.DecodeString(string(payload))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %v", err)
	}
	if len(decoded) < saltLen+nonceLen {
		return nil, fmt.Errorf("truncated encrypted data")
	}

	salt := decoded[:saltLen]
	nonce := decoded[saltLen : saltLen+nonceLen]
	ciphertext := decoded[saltLen+nonceLen:]

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %v", err)
	}
	return plaintext, nil
}
