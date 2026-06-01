// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runFatalChild runs childSetup in a child process expected to call
// log.Fatal (non-zero exit). testName must be the exact function name.
func runFatalChild(t *testing.T, testName, envKey string, childSetup func(t *testing.T)) {
	t.Helper()
	if os.Getenv(envKey) == "1" {
		childSetup(t)
		os.Exit(0) // safety net
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), envKey+"=1")
	if e, ok := cmd.Run().(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("expected child exit error, got nil")
}

// ── Fatal-path negative tests (subprocess) ──────────────────────────

func TestFatal_RenameCollision(t *testing.T) {
	runFatalChild(t, "TestFatal_RenameCollision", "TEST_FATAL_RENAME_COLLISION", func(t *testing.T) {
		t.Setenv("TEST_TMPDIR", os.Getenv("TEST_TMPDIR"))
		dir := os.Getenv("TEST_TMPDIR")
		f := filepath.Join(dir, ".2fa")
		c := &Keychain{
			file: f,
			keys: make(map[string]Key),
			data: []byte("existing 6 JBSWY3DP\n"),
		}
		c.parse(c.data)
		c.rename("existing", "existing") // collision — fatal
	})
}

func TestFatal_RenameSpaces(t *testing.T) {
	runFatalChild(t, "TestFatal_RenameSpaces", "TEST_FATAL_RENAME_SPACES", func(t *testing.T) {
		t.Setenv("TEST_TMPDIR", os.Getenv("TEST_TMPDIR"))
		dir := os.Getenv("TEST_TMPDIR")
		f := filepath.Join(dir, ".2fa")
		c := &Keychain{
			file: f,
			keys: make(map[string]Key),
			data: []byte("old 6 JBSWY3DP\n"),
		}
		c.parse(c.data)
		c.rename("old", "bad name") // spaces — fatal
	})
}

func TestFatal_LookupAmbiguous(t *testing.T) {
	runFatalChild(t, "TestFatal_LookupAmbiguous", "TEST_FATAL_LOOKUP_AMBIGUOUS", func(t *testing.T) {
		c := &Keychain{keys: map[string]Key{"GitHub": {}, "GITHUB": {}}}
		c.lookupKey("github") // ambiguous case — fatal
	})
}

func TestFatal_RemoveNotFound(t *testing.T) {
	runFatalChild(t, "TestFatal_RemoveNotFound", "TEST_FATAL_REMOVE_NOTFOUND", func(t *testing.T) {
		t.Setenv("TEST_TMPDIR", os.Getenv("TEST_TMPDIR"))
		dir := os.Getenv("TEST_TMPDIR")
		f := filepath.Join(dir, ".2fa")
		c := &Keychain{
			file: f,
			keys: make(map[string]Key),
			data: []byte("existing 6 JBSWY3DP\n"),
		}
		c.parse(c.data)
		c.remove("nonexistent") // not found — fatal
	})
}

func TestFatal_CodeNotFound(t *testing.T) {
	runFatalChild(t, "TestFatal_CodeNotFound", "TEST_FATAL_CODE_NOTFOUND", func(t *testing.T) {
		c := &Keychain{keys: make(map[string]Key)}
		c.code("nonexistent") // not found — fatal
	})
}

func TestFatal_InsertKeyBadSecret(t *testing.T) {
	runFatalChild(t, "TestFatal_InsertKeyBadSecret", "TEST_FATAL_INSERTKEY_BAD", func(t *testing.T) {
		t.Setenv("TEST_TMPDIR", os.Getenv("TEST_TMPDIR"))
		dir := os.Getenv("TEST_TMPDIR")
		f := filepath.Join(dir, ".2fa")
		c := &Keychain{
			file: f,
			keys: make(map[string]Key),
		}
		c.insertKey("badkey", "!!!!!!!", 6, false) // invalid base32 — fatal
	})
}
