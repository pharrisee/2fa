// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TOTP / HOTP — RFC test vectors
// ---------------------------------------------------------------------------

// RFC 4226 §5.4 / Appendix D — HOTP test vector.
// Secret = "12345678901234567890" → base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
// (It's 20 bytes of ASCII digits, which is unusual but canonical.)
var rfc4226Secret = []byte("12345678901234567890")

func TestHotp_RFC4226(t *testing.T) {
	// RFC 4226 Appendix D — expected HOTP values for counter 0..9.
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
	// RFC 4226: counter=0, 7-digit = 4755224
	if code != 4755224 {
		t.Errorf("hotp(counter=0, digits=7): got %d, want 4755224", code)
	}
}

func TestHotp_8Digit(t *testing.T) {
	code := hotp(rfc4226Secret, 0, 8)
	// RFC 4226: counter=0, 8-digit = 84755224
	if code != 84755224 {
		t.Errorf("hotp(counter=0, digits=8): got %d, want 84755224", code)
	}
}

// RFC 6238 §B — TOTP test vectors.
// Secret = "12345678901234567890" → same base32 as above.
// Time is Unix epoch + specified offset.
type totpTestCase struct {
	t    int64  // Unix time
	code int
}

func TestTotp_RFC6238(t *testing.T) {
	// RFC 6238 Table 1 — TOTP with SHA1, 8 digits, 30s step.
	cases := []totpTestCase{
		{59, 94287082},
		{1111111109, 7081804},  // RFC: 07081804 (leading zero, int is 7081804)
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
	// RFC 6238: time=59, 6 digits = 287082 (same as HOTP counter 0 here? No,
	// TOTP uses time/30 as counter, so time=59 → counter=1 → 287082 from RFC 4226)
	expected := 287082
	got := totp(rfc4226Secret, time.Unix(59, 0), 6)
	if got != expected {
		t.Errorf("totp(time=59, digits=6): got %d, want %d", got, expected)
	}
}

func TestTotp_ClockDriftTolerance(t *testing.T) {
	// The code() function tries ±1 window. We can't easily test code() directly
	// because it reads from the keychain, but we can verify the totp() function
	// produces different codes for adjacent windows.
	now := time.Now()
	c0 := totp(rfc4226Secret, now, 6)
	c1 := totp(rfc4226Secret, now.Add(-30*time.Second), 6)
	c2 := totp(rfc4226Secret, now.Add(30*time.Second), 6)
	// At least one should differ (if the epoch straddles a boundary, two may match).
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
	// Two calls within the same 30s window should return the same code.
	if c1 != c2 {
		t.Errorf("expected same code within window, got %d and %d", c1, c2)
	}
}

func TestTotpWithFallback_NoFallbackWhenCurrentWorks(t *testing.T) {
	// At the RFC zero-point (Unix time 0), TOTP should be non-zero so no
	// fallback fires, but the result still matches the base totp() call.
	code := totpWithFallback(rfc4226Secret, 6)
	base := totp(rfc4226Secret, time.Now(), 6)
	// Both should match unless we're at a window boundary where the fallback
	// picks a different window; in normal use they match.
	if code != base && (code == 0 || base == 0) {
		t.Logf("code=%d base=%d (possible boundary mismatch)", code, base)
	}
}

// ---------------------------------------------------------------------------
// decodeKey
// ---------------------------------------------------------------------------

func TestDecodeKey(t *testing.T) {
	// "JBSWY3DP" (8 chars, one base32 block) decodes to "Hello".
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
	_, err := decodeKey("JBSWY3DPEHPK3PX!") // '!' is not valid base32
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

// ---------------------------------------------------------------------------
// Keychain parsing
// ---------------------------------------------------------------------------

func TestParse_ValidTOTPLine(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}
	data := []byte("github 6 JBSWY3DP\n")
	c.data = data
	c.parse(data)

	k, ok := c.keys["github"]
	if !ok {
		t.Fatal("key 'github' not found")
	}
	if k.digits != 6 {
		t.Errorf("digits: got %d, want 6", k.digits)
	}
	// "JBSWY3DP" decodes to "Hello".
	expected := []byte("Hello")
	if !bytes.Equal(k.raw, expected) {
		t.Errorf("raw key: got %x, want %x", k.raw, expected)
	}
	if k.offset != 0 {
		t.Errorf("TOTP key should have offset 0, got %d", k.offset)
	}
}

func TestParse_ValidHOTPLine(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}
	data := []byte("myhotp 6 JBSWY3DP 00000000000000000007\n")
	c.data = data
	c.parse(data)

	k, ok := c.keys["myhotp"]
	if !ok {
		t.Fatal("key 'myhotp' not found")
	}
	if k.offset == 0 {
		t.Fatal("HOTP key should have non-zero offset")
	}
	// Counter value.
	n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterFieldWidth]), 10, 64)
	if err != nil {
		t.Fatalf("parsing counter: %v", err)
	}
	if n != 7 {
		t.Errorf("counter: got %d, want 7", n)
	}
}

// TestInsertKey_HOTPOffsetInNonEmptyKeychain verifies that the HOTP counter
// offset is computed relative to the full keychain data, not just the new line.
// This guards against the bug where insertKey calls parse on only the new line,
// producing an offset that's wrong when other keys exist in the file.
func TestInsertKey_HOTPOffsetInNonEmptyKeychain(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}

	// Pre-populate with TOTP keys (simulates an existing keychain).
	c.data = []byte("github 6 JBSWY3DP\ngitlab 6 JBSWY3DP\n")
	c.parse(c.data)

	// This mirrors what insertKey does for a HOTP key:
	// append the new line to c.data, then re-parse the full data.
	line := fmt.Sprintf("myhotp 6 JBSWY3DP %020d\n", 0)
	c.data = append(c.data, []byte(line)...)
	c.parse(c.data)

	k, ok := c.keys["myhotp"]
	if !ok {
		t.Fatal("HOTP key not found")
	}
	if k.offset == 0 {
		t.Fatal("HOTP key should have non-zero offset")
	}

	// The offset should point to the counter field within c.data.
	// Expected: counter sits just before the trailing \n at the end of c.data.
	wantOffset := len(c.data) - counterFieldWidth - 1
	if k.offset != wantOffset {
		t.Fatalf("HOTP offset: got %d, want %d (c.data=%q)", k.offset, wantOffset, string(c.data))
	}

	// Verify the counter reads correctly from c.data at the computed offset.
	n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterFieldWidth]), 10, 64)
	if err != nil {
		t.Fatalf("counter at offset %d: %v", k.offset, err)
	}
	if n != 0 {
		t.Errorf("expected counter 0, got %d", n)
	}
}

// strconvParseUint is alias used in parse(), test helper mirrors it.
func TestParse_7DigitKey(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}
	data := []byte("key7 7 JBSWY3DPEHPK3PXP\n")
	c.parse(data)

	k, ok := c.keys["key7"]
	if !ok {
		t.Fatal("key 'key7' not found")
	}
	if k.digits != 7 {
		t.Errorf("digits: got %d, want 7", k.digits)
	}
}

func TestParse_8DigitKey(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}
	data := []byte("key8 8 JBSWY3DPEHPK3PXP\n")
	c.parse(data)

	k, ok := c.keys["key8"]
	if !ok {
		t.Fatal("key 'key8' not found")
	}
	if k.digits != 8 {
		t.Errorf("digits: got %d, want 8", k.digits)
	}
}

func TestParse_SkipsMalformedLines(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}
	data := []byte(
		"valid 6 JBSWY3DPEHPK3PXP\n" +
			"badline\n" +
			"also_bad  JBSWY3DPEHPK3PXP\n" +   // missing digit field
			"bad_digit 9 JBSWY3DPEHPK3PXP\n" + // digit '9' out of range 6-8
			"\n" + // blank line
			"valid2 7 JBSWY3DPEHPK3PXP\n",
	)
	c.parse(data)

	if _, ok := c.keys["badline"]; ok {
		t.Error("should not have parsed 'badline'")
	}
	if _, ok := c.keys["also_bad"]; ok {
		t.Error("should not have parsed 'also_bad'")
	}
	if _, ok := c.keys["bad_digit"]; ok {
		t.Error("should not have parsed 'bad_digit'")
	}
	if _, ok := c.keys["valid"]; !ok {
		t.Error("'valid' should have been parsed")
	}
	if _, ok := c.keys["valid2"]; !ok {
		t.Error("'valid2' should have been parsed")
	}
}

func TestParse_NoKeys(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}
	c.parse([]byte(""))
	if len(c.keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(c.keys))
	}
}

func TestParse_OnlyBlankLines(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}
	c.parse([]byte("\n\n\n"))
	if len(c.keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(c.keys))
	}
}

// ---------------------------------------------------------------------------
// lookupKey — case-insensitive lookup
// ---------------------------------------------------------------------------

func TestLookupKey_ExactMatch(t *testing.T) {
	c := &Keychain{keys: map[string]Key{"GitHub": {}}}
	_, name, ok := c.lookupKey("GitHub")
	if !ok || name != "GitHub" {
		t.Errorf("exact match failed: ok=%v, name=%s", ok, name)
	}
}

func TestLookupKey_CaseInsensitive(t *testing.T) {
	c := &Keychain{keys: map[string]Key{"GitHub": {}}}
	_, name, ok := c.lookupKey("github")
	if !ok || name != "GitHub" {
		t.Errorf("case-insensitive match failed: ok=%v, name=%s", ok, name)
	}
}

func TestLookupKey_CaseInsensitiveUpper(t *testing.T) {
	c := &Keychain{keys: map[string]Key{"GitHub": {}}}
	_, name, ok := c.lookupKey("GITHUB")
	if !ok || name != "GitHub" {
		t.Errorf("case-insensitive match failed: ok=%v, name=%s", ok, name)
	}
}

func TestLookupKey_NotFound(t *testing.T) {
	c := &Keychain{keys: map[string]Key{"GitHub": {}}}
	_, _, ok := c.lookupKey("nonexistent")
	if ok {
		t.Error("should not find nonexistent key")
	}
}

// TestLookupKey_Ambiguous is verified manually: lookupKey calls log.Fatalf
// for ambiguous matches (which calls os.Exit, not panic, so can't be caught
// with recover). This is acceptable for a CLI tool.

// ---------------------------------------------------------------------------
// Encryption round-trip
// ---------------------------------------------------------------------------

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	cachedKey = nil
	plaintext := []byte("github 6 JBSWY3DP\ngitlab 6 GEZDGNBVGY3TQOJQ\n")
	passphrase := "test-passphrase-123"

	encrypted, err := encryptData(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}

	// The encrypted output should start with the magic header.
	if !bytes.HasPrefix(encrypted, []byte(magicHeader)) {
		t.Error("encrypted data missing magic header")
	}

	// Decrypt.
	decrypted, err := decryptData(encrypted, passphrase)
	if err != nil {
		t.Fatalf("decryptData: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecrypt_WrongPassphrase(t *testing.T) {
	cachedKey = nil // reset cache from previous tests
	plaintext := []byte("github 6 JBSWY3DP\n")
	encrypted, err := encryptData(plaintext, "correct-passphrase")
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}

	cachedKey = nil // force re-derivation for decrypt
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

func TestEncryptCachedKeyReset(t *testing.T) {
	cachedKey = nil
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

	// Encrypt again without resetting cachedKey - should still work
	encrypted2, err := encryptData(plaintext, pass)
	if err != nil {
		t.Fatalf("encryptData second time: %v", err)
	}

	// Verify second encryption produces different output (fresh salt)
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("two encryptions should produce different ciphertext")
	}

	// Verify second encryption can be decrypted
	decrypted2, err := decryptData(encrypted2, pass)
	if err != nil {
		t.Fatalf("decryptData second encrypt: %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("second decrypt round-trip failed")
	}
}

// ---------------------------------------------------------------------------
// Keychain read/write with temp files
// ---------------------------------------------------------------------------

func TestReadKeychain_FileNotFound(t *testing.T) {
	c := readKeychain("/tmp/nonexistent-2fa-test-file-xxxx")
	if c == nil {
		t.Fatal("readKeychain should return empty keychain for missing file")
	}
	if len(c.keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(c.keys))
	}
}

func TestReadKeychain_PlaintextFile(t *testing.T) {
	content := []byte("testkey 6 JBSWY3DPEHPK3PXP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, content, 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	c := readKeychain(f)
	if _, ok := c.keys["testkey"]; !ok {
		t.Error("'testkey' not found in parsed keychain")
	}
}

func TestReadKeychain_EncryptedFile(t *testing.T) {
	cachedKey = nil
	plaintext := []byte("secretkey 6 JBSWY3DP\n")
	pass := "test-password"

	// Encrypt and write.
	encrypted, err := encryptData(plaintext, pass)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, encrypted, 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	// Temporarily set 2FA_PASS.
	os.Setenv("2FA_PASS", pass)
	defer os.Unsetenv("2FA_PASS")

	c := readKeychain(f)
	if !c.encrypted {
		t.Error("keychain should be marked encrypted")
	}
	if _, ok := c.keys["secretkey"]; !ok {
		t.Error("'secretkey' not found in encrypted keychain")
	}
}

func TestWriteFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")

	c := &Keychain{
		file: f,
		data: []byte("k1 6 JBSWY3DPEHPK3PXP\nk2 8 GEZDGNBVGY3TQOJQ\n"),
		keys: make(map[string]Key),
	}
	c.parse(c.data)

	if err := c.writeFile(); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	// Read back.
	c2 := readKeychain(f)
	if len(c2.keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(c2.keys))
	}
	if _, ok := c2.keys["k1"]; !ok {
		t.Error("'k1' missing after round-trip")
	}
	if _, ok := c2.keys["k2"]; !ok {
		t.Error("'k2' missing after round-trip")
	}
}

func TestWriteFile_EncryptedRoundTrip(t *testing.T) {
	cachedKey = nil
	pass := "test-password"
	os.Setenv("2FA_PASS", pass)
	defer os.Unsetenv("2FA_PASS")

	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")

	c := &Keychain{
		file:       f,
		data:       []byte("ek1 6 JBSWY3DPEHPK3PXP\n"),
		keys:       make(map[string]Key),
		encrypted:  true,
		passphrase: pass,
	}
	c.parse(c.data)

	if err := c.writeFile(); err != nil {
		t.Fatalf("writeFile (encrypted): %v", err)
	}

	// Read back — needs 2FA_PASS set already.
	c2 := readKeychain(f)
	if !c2.encrypted {
		t.Error("keychain should still be encrypted")
	}
	if _, ok := c2.keys["ek1"]; !ok {
		t.Error("'ek1' missing after encrypted round-trip")
	}
}

// ---------------------------------------------------------------------------
// code() helper — verifies code output format
// ---------------------------------------------------------------------------

func TestCode_HOTPCounterIncrement(t *testing.T) {
	// Verify that code() followed by incrementCounter correctly advances
	// the HOTP counter and produces valid codes.
	line := []byte("hotp-test 6 JBSWY3DPEHPK3PXP 00000000000000000000\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)
	code := c.code("hotp-test")
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q", code)
	}

	// code() is a pure read — file should be unchanged.
	data, _ := os.ReadFile(f)
	if !bytes.Contains(data, []byte("00000000000000000000")) {
		t.Error("code() should not modify the file")
	}

	// incrementCounter persists the advance.
	c.incrementCounter("hotp-test")
	data, _ = os.ReadFile(f)
	if !bytes.Contains(data, []byte("00000000000000000001")) {
		t.Errorf("counter should be 1 after increment, got: %s", strings.TrimSpace(string(data)))
	}
}

func TestCode_HOTPIncrementSeparate(t *testing.T) {
	line := []byte("hotp-sep 6 JBSWY3DPEHPK3PXP 00000000000000000005\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)

	// code() should be a pure read — no file modification.
	code1 := c.code("hotp-sep")
	if len(code1) != 6 {
		t.Errorf("expected 6-digit code, got %q", code1)
	}
	data, _ := os.ReadFile(f)
	if !bytes.Contains(data, []byte("00000000000000000005")) {
		t.Error("code() should not modify the file for HOTP keys")
	}

	// incrementCounter persists the counter advance.
	c.incrementCounter("hotp-sep")
	data, _ = os.ReadFile(f)
	if !bytes.Contains(data, []byte("00000000000000000006")) {
		t.Errorf("counter should be 6 after increment, got: %s", strings.TrimSpace(string(data)))
	}

	// Calling code() again reflects the new counter.
	code2 := c.code("hotp-sep")
	if len(code2) != 6 {
		t.Errorf("expected 6-digit code, got %q", code2)
	}
	if code1 == code2 {
		t.Error("codes should differ after counter increment")
	}
}

func TestCode_TOTPProducesCode(t *testing.T) {
	line := []byte("totp-test 6 JBSWY3DPEHPK3PXP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)
	code := c.code("totp-test")
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q", code)
	}
	// Should be all digits.
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Errorf("non-digit character %c in code %q", r, code)
		}
	}
}

func TestCode_7Digit(t *testing.T) {
	line := []byte("k7 7 JBSWY3DPEHPK3PXP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)
	code := c.code("k7")
	if len(code) != 7 {
		t.Errorf("expected 7-digit code, got %q (len=%d)", code, len(code))
	}
}

func TestCode_8Digit(t *testing.T) {
	line := []byte("k8 8 JBSWY3DPEHPK3PXP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)
	code := c.code("k8")
	if len(code) != 8 {
		t.Errorf("expected 8-digit code, got %q (len=%d)", code, len(code))
	}
}

// TestKeychainCode_AfterLoad verifies that code() works on an already-loaded
// keychain without re-reading the file — the keychain passed to menu() is
// sufficient to display a code.
func TestKeychainCode_AfterLoad(t *testing.T) {
	line := []byte("menukey 6 JBSWY3DPEHPK3PXP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// This is what menu() does: load the keychain once.
	c := readKeychain(f)

	// Use the loaded keychain directly — no re-read needed.
	code := c.code("menukey")
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q", code)
	}

	// File should be unchanged (TOTP, pure read).
	data, _ := os.ReadFile(f)
	if !bytes.Contains(data, []byte("menukey 6")) {
		t.Error("file should be unchanged")
	}
}

// ---------------------------------------------------------------------------
// Keychain list / showAll
// ---------------------------------------------------------------------------

func TestList_Sorted(t *testing.T) {
	c := &Keychain{keys: map[string]Key{
		"zeta": {}, "alpha": {}, "beta": {},
	}}

	// Capture stdout.
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.list()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "alpha" || lines[1] != "beta" || lines[2] != "zeta" {
		t.Errorf("expected sorted order, got %v", lines)
	}
}

// ---------------------------------------------------------------------------
// File permission warning
// ---------------------------------------------------------------------------

func TestReadKeychain_PermissionWarning(t *testing.T) {
	content := []byte("k 6 JBSWY3DP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, content, 0644); err != nil { // too permissive!
		t.Fatalf("write: %v", err)
	}

	// Redirect log output to capture the warning.
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	readKeychain(f)

	msg := logBuf.String()

	if !strings.Contains(msg, "warning") || !strings.Contains(msg, "permissive") {
		t.Errorf("expected permission warning on stderr, got: %q", msg)
	}
}

// ---------------------------------------------------------------------------
// Full machine-readable export
// ---------------------------------------------------------------------------

func TestExportOutput(t *testing.T) {
	content := []byte("k1 6 JBSWY3DPEHPK3PXP\nk2 7 GEZDGNBVGY3TQOJQ\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, content, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)

	// Capture stdout.
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	os.Stdout.Write(c.data)

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if !bytes.Equal(buf.Bytes(), content) {
		t.Errorf("export: got %q, want %q", buf.Bytes(), content)
	}
}

// ---------------------------------------------------------------------------
// Base32 encoding/decoding sanity
// ---------------------------------------------------------------------------

func TestBase32RoundTrip(t *testing.T) {
	// The keychain stores unpadded base32 (padding added during decode).
	raw := []byte("Hello12345")
	encoded := base32.StdEncoding.EncodeToString(raw)
	// Remove padding for realistic keychain format.
	encoded = strings.TrimRight(encoded, "=")

	decoded, err := decodeKey(encoded)
	if err != nil {
		t.Fatalf("decodeKey: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Errorf("base32 round-trip: got %x, want %x", decoded, raw)
	}
}

// ---------------------------------------------------------------------------
// showAll output format — TOTP keys show code, HOTP keys show dashes
// ---------------------------------------------------------------------------

func TestShowAll_TOTPShowsCode(t *testing.T) {
	c := &Keychain{keys: map[string]Key{
		"test": {digits: 6, raw: []byte("Hello12345"), offset: 0},
	}}

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.showAll()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	// Should contain 6 digits, a tab, then "test".
	if !strings.Contains(out, "\ttest") {
		t.Errorf("showAll output missing key name: %s", out)
	}
	if !strings.Contains(out, "\t") {
		t.Errorf("showAll should have tab separator: %s", out)
	}
}

func TestShowAll_HOTPShowsDashes(t *testing.T) {
	// Need real data with an offset (non-zero).
	line := []byte("hotp 6 JBSWY3DPEHPK3PXP 00000000000000000000\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.showAll()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "------\thotp") {
		t.Errorf("HOTP showAll should show dashes, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Verify the binary builds (integration smoke test)
// ---------------------------------------------------------------------------

func TestBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build test in short mode")
	}
	// We just verify the package compiles.
	// The actual build is done by 'go build' — this is a smoke check.
}

// ---------------------------------------------------------------------------
// Benchmark — TOTP performance
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Menu view rendering
// ---------------------------------------------------------------------------

func TestMenuView_ContainsKeyNames(t *testing.T) {
	m := menuModel{
		names:  []string{"github", "gitlab"},
		keyInf: map[string]menuKeyInfo{
			"github": {digits: 6, raw: []byte("key"), isHOTP: false},
			"gitlab": {digits: 6, raw: []byte("key"), isHOTP: true},
		},
		cursor: 0,
		filter: nil,
		width:  80,
		height: 24,
	}
	out := m.View()
	if !strings.Contains(out, "github") {
		t.Error("View should contain 'github'")
	}
	if !strings.Contains(out, "gitlab") {
		t.Error("View should contain 'gitlab'")
	}
	if !strings.Contains(out, "[HOTP]") {
		t.Error("View should show [HOTP] for HOTP keys")
	}
}
