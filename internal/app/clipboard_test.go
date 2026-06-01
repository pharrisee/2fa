// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"testing"
)

func TestFindExe_Found(t *testing.T) {
	// "sh" should exist on any Unix-like system.
	if !findExe("sh") {
		t.Error("expected 'sh' to be found")
	}
}

func TestFindExe_NotFound(t *testing.T) {
	if findExe("nonexistent-command-xyz123") {
		t.Error("expected nonexistent command to not be found")
	}
}
