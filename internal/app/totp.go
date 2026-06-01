// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.Unix()/30), digits)
}

// totpWithFallback computes a TOTP code with ±1 window tolerance.
// If the current window gives 0, it tries the previous and next windows.
func totpWithFallback(key []byte, digits int) int {
	now := time.Now()
	code := totp(key, now, digits)
	if code == 0 {
		code = totp(key, now.Add(-30*time.Second), digits)
	}
	if code == 0 {
		code = totp(key, now.Add(30*time.Second), digits)
	}
	return code
}

// parseOTPURI parses an otpauth:// URI into key name, secret, digit count,
// and whether it's HOTP.  No new dependencies — uses net/url from stdlib.
func parseOTPURI(uri string) (name string, secret string, digits int, hotp bool, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", 0, false, fmt.Errorf("parsing URI: %v", err)
	}
	if u.Scheme != "otpauth" {
		return "", "", 0, false, fmt.Errorf("unsupported URI scheme %q", u.Scheme)
	}

	switch u.Host {
	case "totp":
		hotp = false
	case "hotp":
		hotp = true
	default:
		return "", "", 0, false, fmt.Errorf("unsupported OTP type %q", u.Host)
	}

	secret = u.Query().Get("secret")
	if secret == "" {
		return "", "", 0, false, fmt.Errorf("no secret in URI")
	}

	digits = 6
	if d := u.Query().Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 6 || n > 8 {
			return "", "", 0, false, fmt.Errorf("invalid digits %q", d)
		}
		digits = n
	}

	// Determine key name: issuer query param first, then label component before ":".
	name = u.Query().Get("issuer")
	if name == "" {
		label := strings.TrimPrefix(u.Path, "/")
		if idx := strings.LastIndex(label, ":"); idx >= 0 {
			name = label[:idx]
		} else {
			name = label
		}
	}
	if name == "" {
		return "", "", 0, false, fmt.Errorf("could not determine key name from URI")
	}

	return name, secret, digits, hotp, nil
}
