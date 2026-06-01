// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func writeClipboard(s string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "windows":
		cmd = exec.Command("clip")
	default:
		switch {
		case findExe("wl-copy"):
			cmd = exec.Command("wl-copy")
		case findExe("xclip"):
			cmd = exec.Command("xclip", "-selection", "clipboard")
		case findExe("xsel"):
			cmd = exec.Command("xsel", "-ib")
		default:
			return fmt.Errorf("no clipboard tool found (install wl-copy, xclip, or xsel)")
		}
	}
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run()
}

func findExe(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
