// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_List(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, []byte("github 6 JBSWY3DP\ngitlab 6 JBSWY3DP\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("2FA_FILE", f)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	openKeychain().list()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "github") || !strings.Contains(out, "gitlab") {
		t.Errorf("list output missing keys: %q", out)
	}
}

func TestCLI_ValidateEmpty(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	t.Setenv("2FA_FILE", f)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	openKeychain().validate()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "empty") {
		t.Errorf("expected 'empty' for empty keychain, got: %q", out)
	}
}

func TestCLI_AddAndList(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	t.Setenv("2FA_FILE", f)

	c := openKeychain()
	c.insertKey("testkey", "JBSWY3DP", 6, false)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	c.list()

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "testkey") {
		t.Errorf("list should include 'testkey', got: %q", out)
	}
}

func TestAppVersion_ReturnsDevByDefault(t *testing.T) {
	v := appVersion()
	// In test context, no ldflags or build info version is set, so it should be "dev".
	if v != "dev" {
		t.Errorf("expected 'dev', got %q", v)
	}
}

func TestShowByName_RejectsSpaces(t *testing.T) {
	err := showByName("bad name")
	if err == nil {
		t.Fatal("expected error for name with spaces")
	}
	if !strings.Contains(err.Error(), "spaces") {
		t.Errorf("expected 'spaces' in error, got %v", err)
	}
}

func TestShowByName_HappyPath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	if err := os.WriteFile(f, []byte("testkey 6 JBSWY3DPEHPK3PXP\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("2FA_FILE", f)

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w

	err := showByName("testkey")

	w.Close()
	os.Stdout = stdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	if err != nil {
		t.Fatalf("showByName: %v", err)
	}
	if len(out) < 6 {
		t.Errorf("expected 6+ char code, got %q", out)
	}
}

func TestWriteFile_EncryptedUpgrade(t *testing.T) {
	// When 2FA_PASS is set and file is plaintext, readKeychain marks
	// useEncryption=true, and writeFile encrypts on write.
	pass := "test-password"
	os.Setenv("2FA_PASS", pass)
	defer os.Unsetenv("2FA_PASS")

	dir := t.TempDir()
	f := filepath.Join(dir, ".2fa")
	plaintext := []byte("upgrade 6 JBSWY3DP\n")
	if err := os.WriteFile(f, plaintext, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := readKeychain(f)
	if !c.useEncryption {
		t.Fatal("keychain should be marked encrypted when 2FA_PASS is set")
	}

	// Write should encrypt.
	if err := c.writeFile(); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	// Verify file on disk is encrypted.
	disk, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.HasPrefix(disk, []byte(magicHeader)) {
		t.Error("file on disk should have magic header after encrypted write")
	}
}
