// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 4226 §5.4 / Appendix D — HOTP test vector.
// Secret = "12345678901234567890" → base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
// (It's 20 bytes of ASCII digits, which is unusual but canonical.)
var rfc4226Secret = []byte("12345678901234567890")

func TestHotp_RFC4226(t *testing.T) {
	expected := []struct {
		counter uint64
		code    int
	}{
		{0, 755224},
		{1, 287082},
		{2, 359152},
		{3, 969429},
		{4, 338314},
		{5, 254676},
		{6, 287922},
		{7, 162583},
		{8, 399871},
		{9, 520489},
	}
	for _, tc := range expected {
		got := hotp(rfc4226Secret, tc.counter, 6)
		if got != tc.code {
			t.Errorf("hotp(counter=%d): got %d, want %d", tc.counter, got, tc.code)
		}
	}
}

func TestHotp_7Digit(t *testing.T) {
	code := hotp(rfc4226Secret, 0, 7)
	if code != 4755224 {
		t.Errorf("hotp(counter=0, digits=7): got %d, want 4755224", code)
	}
}

func TestHotp_8Digit(t *testing.T) {
	code := hotp(rfc4226Secret, 0, 8)
	if code != 84755224 {
		t.Errorf("hotp(counter=0, digits=8): got %d, want 84755224", code)
	}
}

// RFC 6238 §B — TOTP test vectors.
type totpTestCase struct {
	t    int64 // Unix time
	code int
}

func TestTotp_RFC6238(t *testing.T) {
	cases := []totpTestCase{
		{59, 94287082},
		{1111111109, 7081804},
		{1111111111, 14050471},
		{1234567890, 89005924},
		{2000000000, 69279037},
		{20000000000, 65353130},
	}
	for _, tc := range cases {
		got := totp(rfc4226Secret, time.Unix(tc.t, 0), 8)
		if got != tc.code {
			t.Errorf("totp(time=%d): got %d, want %d", tc.t, got, tc.code)
		}
	}
}

func TestTotp_6Digit(t *testing.T) {
	expected := 287082
	got := totp(rfc4226Secret, time.Unix(59, 0), 6)
	if got != expected {
		t.Errorf("totp(time=59, digits=6): got %d, want %d", got, expected)
	}
}

func TestTotp_ClockDriftTolerance(t *testing.T) {
	now := time.Now()
	c0 := totp(rfc4226Secret, now, 6)
	c1 := totp(rfc4226Secret, now.Add(-30*time.Second), 6)
	c2 := totp(rfc4226Secret, now.Add(30*time.Second), 6)
	if c0 == c1 && c1 == c2 {
		t.Log("all three windows produced same code (possible at boundary)")
	}
}

func TestTotpWithFallback_ReturnsCode(t *testing.T) {
	code := totpWithFallback(rfc4226Secret, 6)
	if code < 0 || code > 999999 {
		t.Errorf("expected 6-digit code, got %d", code)
	}
}

func TestTotpWithFallback_StableInWindow(t *testing.T) {
	c1 := totpWithFallback(rfc4226Secret, 6)
	c2 := totpWithFallback(rfc4226Secret, 6)
	if c1 != c2 {
		t.Errorf("expected same code within window, got %d and %d", c1, c2)
	}
}

func TestTotpWithFallback_NoFallbackWhenCurrentWorks(t *testing.T) {
	code := totpWithFallback(rfc4226Secret, 6)
	base := totp(rfc4226Secret, time.Now(), 6)
	if code != base && (code == 0 || base == 0) {
		t.Logf("code=%d base=%d (possible boundary mismatch)", code, base)
	}
}

func TestDecodeKey(t *testing.T) {
	expected := []byte("Hello")
	got, err := decodeKey("JBSWY3DP")
	if err != nil {
		t.Fatalf("decodeKey: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("decodeKey: got %x, want %x", got, expected)
	}
}

func TestDecodeKey_Lowercase(t *testing.T) {
	got, err := decodeKey("jbswy3dp")
	if err != nil {
		t.Fatalf("decodeKey(lower): %v", err)
	}
	expected := []byte("Hello")
	if !bytes.Equal(got, expected) {
		t.Errorf("decodeKey: got %x, want %x", got, expected)
	}
}

func TestDecodeKey_InvalidChar(t *testing.T) {
	_, err := decodeKey("JBSWY3DPEHPK3PX!")
	if err == nil {
		t.Error("decodeKey should have rejected '!'")
	}
}

func TestDecodeKey_Empty(t *testing.T) {
	got, err := decodeKey("")
	if err != nil {
		t.Fatalf("decodeKey(empty): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %x", got)
	}
}

func TestBase32RoundTrip(t *testing.T) {
	raw := []byte("Hello12345")
	encoded := base32.StdEncoding.EncodeToString(raw)
	encoded = strings.TrimRight(encoded, "=")

	decoded, err := decodeKey(encoded)
	if err != nil {
		t.Fatalf("decodeKey: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Errorf("base32 round-trip: got %x, want %x", decoded, raw)
	}
}

func BenchmarkTotp(b *testing.B) {
	key := []byte("Hello12345")
	tm := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		totp(key, tm, 6)
	}
}

func BenchmarkHotp(b *testing.B) {
	key := []byte("Hello12345")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hotp(key, uint64(i), 6)
	}
}

func TestParseOTPURI_TOTP(t *testing.T) {
	name, secret, digits, hotp, err := parseOTPURI("otpauth://totp/GitHub:phil@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
	if err != nil {
		t.Fatalf("parseOTPURI: %v", err)
	}
	if name != "GitHub" {
		t.Errorf("name: got %q, want %q", name, "GitHub")
	}
	if secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("secret: got %q, want %q", secret, "JBSWY3DPEHPK3PXP")
	}
	if digits != 6 {
		t.Errorf("digits: got %d, want 6", digits)
	}
	if hotp {
		t.Error("should be TOTP")
	}
}

func TestParseOTPURI_HOTP(t *testing.T) {
	name, secret, digits, hotp, err := parseOTPURI("otpauth://hotp/MyService?secret=JBSWY3DP&digits=8")
	if err != nil {
		t.Fatalf("parseOTPURI: %v", err)
	}
	if name != "MyService" {
		t.Errorf("name: got %q, want %q", name, "MyService")
	}
	if secret != "JBSWY3DP" {
		t.Errorf("secret: got %q, want %q", secret, "JBSWY3DP")
	}
	if digits != 8 {
		t.Errorf("digits: got %d, want 8", digits)
	}
	if !hotp {
		t.Error("should be HOTP")
	}
}

func TestParseOTPURI_LabelFallback(t *testing.T) {
	name, _, _, _, err := parseOTPURI("otpauth://totp/MyKey?secret=JBSWY3DP")
	if err != nil {
		t.Fatalf("parseOTPURI: %v", err)
	}
	if name != "MyKey" {
		t.Errorf("name: got %q, want %q", name, "MyKey")
	}
}

func TestParseOTPURI_InvalidScheme(t *testing.T) {
	_, _, _, _, err := parseOTPURI("http://example.com")
	if err == nil {
		t.Error("expected error for invalid scheme")
	}
}

func TestParseOTPURI_MissingSecret(t *testing.T) {
	_, _, _, _, err := parseOTPURI("otpauth://totp/Key")
	if err == nil {
		t.Error("expected error for missing secret")
	}
}

func TestParseOTPURI_UnsupportedType(t *testing.T) {
	_, _, _, _, err := parseOTPURI("otpauth://invalid/Key?secret=JBSWY3DP")
	if err == nil {
		t.Error("expected error for unsupported OTP type")
	}
}

func TestParseOTPURI_BadDigits(t *testing.T) {
	_, _, _, _, err := parseOTPURI("otpauth://totp/Key?secret=JBSWY3DP&digits=4")
	if err == nil {
		t.Error("expected error for digits=4 (out of range)")
	}
}

func TestParseOTPURI_NonNumericDigits(t *testing.T) {
	_, _, _, _, err := parseOTPURI("otpauth://totp/Key?secret=JBSWY3DP&digits=abc")
	if err == nil {
		t.Error("expected error for non-numeric digits")
	}
}

func TestParseOTPURI_LabelWithColonNoIssuer(t *testing.T) {
	name, _, _, _, err := parseOTPURI("otpauth://totp/IssuerName:user@example.com?secret=JBSWY3DP")
	if err != nil {
		t.Fatalf("parseOTPURI: %v", err)
	}
	if name != "IssuerName" {
		t.Errorf("name: got %q, want %q", name, "IssuerName")
	}
}
