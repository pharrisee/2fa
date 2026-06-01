// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// captureStdout captures stdout during fn() and returns the output.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = stdout
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}


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
	n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterFieldWidth]), 10, 64)
	if err != nil {
		t.Fatalf("parsing counter: %v", err)
	}
	if n != 7 {
		t.Errorf("counter: got %d, want 7", n)
	}
}

func TestInsertKey_HOTPOffsetInNonEmptyKeychain(t *testing.T) {
	c := &Keychain{keys: make(map[string]Key)}
	c.data = []byte("github 6 JBSWY3DP\ngitlab 6 JBSWY3DP\n")
	c.parse(c.data)

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
	wantOffset := len(c.data) - counterFieldWidth - 1
	if k.offset != wantOffset {
		t.Fatalf("HOTP offset: got %d, want %d (c.data=%q)", k.offset, wantOffset, string(c.data))
	}
	n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterFieldWidth]), 10, 64)
	if err != nil {
		t.Fatalf("counter at offset %d: %v", k.offset, err)
	}
	if n != 0 {
		t.Errorf("expected counter 0, got %d", n)
	}
}

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
			"also_bad  JBSWY3DPEHPK3PXP\n" +
			"bad_digit 9 JBSWY3DPEHPK3PXP\n" +
			"\n" +
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
	plaintext := []byte("secretkey 6 JBSWY3DP\n")
	pass := "test-password"

	encrypted, err := encryptData(plaintext, pass)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, encrypted, 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	os.Setenv("2FA_PASS", pass)
	defer os.Unsetenv("2FA_PASS")

	c := readKeychain(f)
	if !c.useEncryption {
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
	pass := "test-password"
	os.Setenv("2FA_PASS", pass)
	defer os.Unsetenv("2FA_PASS")

	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")

	c := &Keychain{
		file:       f,
		data:       []byte("ek1 6 JBSWY3DPEHPK3PXP\n"),
		keys:       make(map[string]Key),
		useEncryption: true,
		passphrase: pass,
	}
	c.parse(c.data)

	if err := c.writeFile(); err != nil {
		t.Fatalf("writeFile (encrypted): %v", err)
	}

	c2 := readKeychain(f)
	if !c2.useEncryption {
		t.Error("keychain should still be encrypted")
	}
	if _, ok := c2.keys["ek1"]; !ok {
		t.Error("'ek1' missing after encrypted round-trip")
	}
}

func TestCode_HOTPCounterIncrement(t *testing.T) {
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

	data, _ := os.ReadFile(f)
	if !bytes.Contains(data, []byte("00000000000000000000")) {
		t.Error("code() should not modify the file")
	}

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

	code1 := c.code("hotp-sep")
	if len(code1) != 6 {
		t.Errorf("expected 6-digit code, got %q", code1)
	}
	data, _ := os.ReadFile(f)
	if !bytes.Contains(data, []byte("00000000000000000005")) {
		t.Error("code() should not modify the file for HOTP keys")
	}

	c.incrementCounter("hotp-sep")
	data, _ = os.ReadFile(f)
	if !bytes.Contains(data, []byte("00000000000000000006")) {
		t.Errorf("counter should be 6 after increment, got: %s", strings.TrimSpace(string(data)))
	}

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

func TestKeychainCode_AfterLoad(t *testing.T) {
	line := []byte("menukey 6 JBSWY3DPEHPK3PXP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)
	code := c.code("menukey")
	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q", code)
	}

	data, _ := os.ReadFile(f)
	if !bytes.Contains(data, []byte("menukey 6")) {
		t.Error("file should be unchanged")
	}
}

func TestList_Sorted(t *testing.T) {
	c := &Keychain{keys: map[string]Key{
		"zeta": {}, "alpha": {}, "beta": {},
	}}

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

func TestReadKeychain_PermissionWarning(t *testing.T) {
	content := []byte("k 6 JBSWY3DP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(os.Stderr)

	readKeychain(f)

	msg := logBuf.String()

	if !strings.Contains(msg, "warning") || !strings.Contains(msg, "permissive") {
		t.Errorf("expected permission warning on stderr, got: %q", msg)
	}
}

func TestExportOutput(t *testing.T) {
	content := []byte("k1 6 JBSWY3DPEHPK3PXP\nk2 7 GEZDGNBVGY3TQOJQ\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, content, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)

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

	if !strings.Contains(out, "\ttest") {
		t.Errorf("showAll output missing key name: %s", out)
	}
	if !strings.Contains(out, "\t") {
		t.Errorf("showAll should have tab separator: %s", out)
	}
}

func TestShowAll_HOTPShowsDashes(t *testing.T) {
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

func TestNoSpace_StripsWhitespace(t *testing.T) {
	if noSpace(' ') != -1 {
		t.Error("space should be stripped")
	}
	if noSpace('\t') != -1 {
		t.Error("tab should be stripped")
	}
	if noSpace('\n') != -1 {
		t.Error("newline should be stripped")
	}
	if noSpace('a') != 'a' {
		t.Error("non-space should pass through")
	}
}

func TestRemove_RemovesKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	c := &Keychain{
		file: f,
		keys: make(map[string]Key),
		data: []byte("alpha 6 JBSWY3DP\nbeta 6 JBSWY3DP\n"),
	}
	c.parse(c.data)

	c.remove("alpha")

	if _, ok := c.keys["alpha"]; ok {
		t.Error("'alpha' should have been removed")
	}
	if _, ok := c.keys["beta"]; !ok {
		t.Error("'beta' should still exist")
	}
}

func TestRename_RenamesKey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	c := &Keychain{
		file: f,
		keys: make(map[string]Key),
		data: []byte("oldname 6 JBSWY3DP\n"),
	}
	c.parse(c.data)

	c.rename("oldname", "newname")

	if _, ok := c.keys["oldname"]; ok {
		t.Error("'oldname' should have been renamed")
	}
	if _, ok := c.keys["newname"]; !ok {
		t.Error("'newname' should exist after rename")
	}
}

func TestShow_PrintsCode(t *testing.T) {
	line := []byte("showtest 6 JBSWY3DPEHPK3PXP\n")
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, line, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.show("showtest")

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if len(out) < 6 {
		t.Errorf("expected 6+ char code, got %q", out)
	}
}

func TestValidate_ValidKeychain(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("alpha 6 JBSWY3DPEHPK3PXP\nbeta 7 GEZDGNBVGY3TQOJQ\nhotpkey 6 JBSWY3DP 00000000000000000005\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "valid") {
		t.Errorf("expected 'valid' in output, got: %q", out)
	}
	if !strings.Contains(out, "3 key") {
		t.Errorf("expected '3 key(s)', got: %q", out)
	}
}

func TestValidate_TooFewFields(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("partial 6\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "too few fields") {
		t.Errorf("expected 'too few fields' in output, got: %q", out)
	}
}

func TestValidate_BadDigitCount(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("bad 5 JBSWY3DP\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "invalid digit count") {
		t.Errorf("expected 'invalid digit count' in output, got: %q", out)
	}
}

func TestValidate_InvalidBase32(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("bad 6 !!!!!!!!\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "invalid base32") {
		t.Errorf("expected 'invalid base32' in output, got: %q", out)
	}
}

func TestValidate_BadCounterWidth(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("bad 6 JBSWY3DP 123\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "counter field width") {
		t.Errorf("expected 'counter field width' in output, got: %q", out)
	}
}

func TestValidate_BadCounterValue(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("bad 6 JBSWY3DP !!!!!!!!!!!!!!!!!!!!\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "invalid counter value") {
		t.Errorf("expected 'invalid counter value' in output, got: %q", out)
	}
}

func TestValidate_DuplicateName(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("dup 6 JBSWY3DP\nalso 6 JBSWY3DPEHPK3PXP\ndup 6 JBSWY3DP\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "duplicate key name") {
		t.Errorf("expected 'duplicate key name' in output, got: %q", out)
	}
}

func TestValidate_TooManyFields(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("extra 6 JBSWY3DP 00000000000000000000 bonus\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "too many fields") {
		t.Errorf("expected 'too many fields' in output, got: %q", out)
	}
}

func TestValidate_EmptyKeyName(t *testing.T) {
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte(" 6 JBSWY3DP\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "empty key name") {
		t.Errorf("expected 'empty key name' in output, got: %q", out)
	}
}

func TestKeychainPath_WithEnv(t *testing.T) {
	custom := "/tmp/my-custom-2fa-file"
	t.Setenv("2FA_FILE", custom)
	got := keychainPath()
	if got != custom {
		t.Errorf("keychainPath with 2FA_FILE: got %q, want %q", got, custom)
	}
}

func TestWriteFile_EncryptedNoPassphrase(t *testing.T) {
	c := &Keychain{useEncryption: true, passphrase: ""}
	err := c.writeFile()
	if err == nil {
		t.Error("expected error for encrypted write with no passphrase")
	}
	if !strings.Contains(err.Error(), "no passphrase") {
		t.Errorf("expected 'no passphrase' error, got: %v", err)
	}
}

func TestParse_HOTPNoTrailingNewline(t *testing.T) {
	// Last line without trailing \n — counter offset still works.
	c := &Keychain{keys: make(map[string]Key)}
	data := []byte("hotp 6 JBSWY3DP 00000000000000000042")
	c.data = data
	c.parse(data)

	k, ok := c.keys["hotp"]
	if !ok {
		t.Fatal("HOTP key not found")
	}
	if k.offset == 0 {
		t.Fatal("HOTP key should have non-zero offset")
	}
	n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterFieldWidth]), 10, 64)
	if err != nil {
		t.Fatalf("parsing counter: %v", err)
	}
	if n != 42 {
		t.Errorf("counter: got %d, want 42", n)
	}
}

func TestValidate_CountsValidKeysCorrectly(t *testing.T) {
	// Two valid keys, one blank line — should report 2 valid.
	c := &Keychain{
		keys: make(map[string]Key),
		data: []byte("a 6 JBSWY3DP\n\nb 6 JBSWY3DP\n"),
	}
	c.parse(c.data)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "2 key(s)") {
		t.Errorf("expected '2 key(s)', got: %q", out)
	}
}

