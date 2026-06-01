// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Keychain represents a parsed 2fa keychain file.
type Keychain struct {
	file       string
	data       []byte // raw file content (plaintext, after decryption if applicable)
	keys       map[string]Key
	encrypted  bool   // whether the file on disk is encrypted
	passphrase string // cached passphrase, empty = no encryption
}

// Key represents a single TOTP or HOTP key in the keychain.
type Key struct {
	raw    []byte
	digits int
	offset int // offset of counter field in raw data
}

func readKeychain(file string) *Keychain {
	c := &Keychain{
		file: file,
		keys: make(map[string]Key),
	}

	rawFile, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return c
		}
		log.Fatal(err)
	}

	// Check file permissions and warn if too permissive.
	if fi, statErr := os.Stat(file); statErr == nil {
		if fi.Mode().Perm()&0077 != 0 {
			log.Printf("warning: %s has overly permissive permissions (%#o); consider chmod 600", filepath.Base(file), fi.Mode().Perm())
		}
	}

	// Check for encryption magic header.
	var plaintext []byte
	pass := os.Getenv("2FA_PASS")
	if bytes.HasPrefix(rawFile, []byte(magicHeader)) {
		if pass == "" {
			log.Fatalf("%s is encrypted but 2FA_PASS environment variable is not set", filepath.Base(file))
		}
		c.encrypted = true
		c.passphrase = pass
		plaintext, err = decryptData(rawFile, pass)
		if err != nil {
			log.Fatalf("decrypting keychain: %v", err)
		}
	} else {
		plaintext = rawFile
		if pass != "" {
			c.encrypted = true
			c.passphrase = pass
		}
	}

	c.data = plaintext
	c.parse(plaintext)
	return c
}

func (c *Keychain) parse(data []byte) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		lineno := i + 1
		offset += len(line)

		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if len(f) == 1 && len(f[0]) == 0 {
			continue
		}
		if len(f) >= 3 && len(f[1]) == 1 && '6' <= f[1][0] && f[1][0] <= '8' {
			var k Key
			name := string(f[0])
			k.digits = int(f[1][0] - '0')
			raw, err := decodeKey(string(f[2]))
			if err == nil {
				k.raw = raw
				if len(f) == 3 {
					c.keys[name] = k
					continue
				}
				if len(f) == 4 && len(f[3]) == counterFieldWidth {
					_, err := strconv.ParseUint(string(f[3]), 10, 64)
					if err == nil {
						k.offset = offset - counterFieldWidth
						if line[len(line)-1] == '\n' {
							k.offset--
						}
						c.keys[name] = k
						continue
					}
				}
			}
		}
		log.Printf("%s:%d: malformed key", filepath.Base(c.file), lineno)
	}
}

// writeFile atomically writes the in-memory keychain data to disk,
// encrypting if encryption is enabled.
func (c *Keychain) writeFile() error {
	data := c.data
	if c.encrypted {
		if c.passphrase == "" {
			return fmt.Errorf("cannot write encrypted keychain: no passphrase")
		}
		var err error
		data, err = encryptData(data, c.passphrase)
		if err != nil {
			return fmt.Errorf("encrypting keychain: %v", err)
		}
	}
	// Write atomically via temp file + rename to avoid partial writes.
	tmp, err := os.CreateTemp(filepath.Dir(c.file), ".2fa.tmp.*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()           //nolint:errcheck // best-effort cleanup
		os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()           //nolint:errcheck // best-effort cleanup
		os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup
		return err
	}
	if err := os.Rename(tmp.Name(), c.file); err != nil {
		os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup
		return err
	}
	return nil
}

func (c *Keychain) list() {
	names := c.sortedKeyNames()
	for _, name := range names {
		fmt.Println(name)
	}
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

// add reads a secret from stdin and adds a key.
func (c *Keychain) add(name string, size int, hotp bool) {
	fmt.Fprintf(os.Stderr, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	c.insertKey(name, strings.Map(noSpace, text), size, hotp)
}

// insertKey adds a key with the given raw secret text and writes the file.
func (c *Keychain) insertKey(name, rawSecret string, size int, hotp bool) {
	rawSecret += strings.Repeat("=", -len(rawSecret)&7) // pad to multiple of 8
	if _, err := decodeKey(rawSecret); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	line := fmt.Sprintf("%s %d %s", name, size, strings.ToUpper(rawSecret))
	if hotp {
		line += " " + strings.Repeat("0", counterFieldWidth)
	}
	line += "\n"

	c.data = append(c.data, []byte(line)...)
	c.parse(c.data)

	if err := c.writeFile(); err != nil {
		log.Fatalf("adding key: %v", err)
	}
}

// lookupKey finds a key by name, falling back to case-insensitive match.
// Returns the key, the canonical name as stored, and whether found.
func (c *Keychain) lookupKey(name string) (Key, string, bool) {
	if k, ok := c.keys[name]; ok {
		return k, name, true
	}
	// Case-insensitive fallback.
	lower := strings.ToLower(name)
	var match string
	for stored := range c.keys {
		if strings.ToLower(stored) == lower {
			if match != "" {
				log.Fatalf("ambiguous key %q: matches both %q and %q", name, match, stored)
			}
			match = stored
		}
	}
	if match != "" {
		k := c.keys[match]
		return k, match, true
	}
	return Key{}, "", false
}

func (c *Keychain) code(name string) string {
	k, storedName, ok := c.lookupKey(name)
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	name = storedName
	var code int
	if k.offset != 0 {
		// HOTP: pure read — use current counter without advancing.
		n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterFieldWidth]), 10, 64)
		if err != nil {
			log.Fatalf("malformed key counter for %q (%q)", name, c.data[k.offset:k.offset+counterFieldWidth])
		}
		code = hotp(k.raw, n, k.digits)
	} else {
		// Time-based key (TOTP) with ±1 window tolerance.
		code = totpWithFallback(k.raw, k.digits)
	}
	return fmt.Sprintf("%0*d", k.digits, code)
}

// incrementCounter advances the HOTP counter for the given key and persists
// the change. It is a no-op for TOTP keys.
func (c *Keychain) incrementCounter(name string) {
	k, storedName, ok := c.lookupKey(name)
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	if k.offset == 0 {
		return // TOTP keys don't have counters
	}
	name = storedName

	n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterFieldWidth]), 10, 64)
	if err != nil {
		log.Fatalf("malformed key counter for %q (%q)", name, c.data[k.offset:k.offset+counterFieldWidth])
	}
	n++

	newCounter := []byte(fmt.Sprintf("%0*d", counterFieldWidth, n))
	newData := make([]byte, len(c.data))
	copy(newData, c.data)
	copy(newData[k.offset:k.offset+counterFieldWidth], newCounter)

	c.data = newData
	c.keys = make(map[string]Key)
	c.parse(c.data)

	if err := c.writeFile(); err != nil {
		log.Fatalf("updating keychain: %v", err)
	}
}

func (c *Keychain) show(name string) {
	code := c.code(name)
	c.incrementCounter(name)
	if err := writeClipboard(code); err != nil {
		log.Printf("warning: clipboard copy failed: %v", err)
	}
	fmt.Printf("%s\n", code)
}

func (c *Keychain) showAll() {
	names := c.sortedKeyNames()
	maxLen := 0
	for _, name := range names {
		k := c.keys[name]
		if maxLen < k.digits {
			maxLen = k.digits
		}
	}
	for _, name := range names {
		k := c.keys[name]
		var code string
		if k.offset == 0 {
			// TOTP: compute live code with ±1 window tolerance.
			code = fmt.Sprintf("%0*d", k.digits, totpWithFallback(k.raw, k.digits))
		} else {
			// HOTP: cannot show without consuming the counter.
			code = strings.Repeat("-", k.digits)
		}
		fmt.Printf("%-*s\t%s\n", maxLen, code, name)
	}
}

// remove deletes a key by name from the keychain.
func (c *Keychain) remove(name string) {
	_, storedName, ok := c.lookupKey(name)
	if !ok {
		log.Fatalf("no such key %q", name)
	}

	var buf bytes.Buffer
	lines := bytes.SplitAfter(c.data, []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		trimmed := bytes.TrimSuffix(line, []byte("\n"))
		f := bytes.SplitN(trimmed, []byte(" "), 2)
		if len(f) >= 1 && string(f[0]) == storedName {
			continue // skip this line
		}
		buf.Write(line)
	}

	c.data = buf.Bytes()
	c.keys = make(map[string]Key)
	c.parse(c.data)
	if err := c.writeFile(); err != nil {
		log.Fatalf("deleting key: %v", err)
	}
	log.Printf("deleted key %q", storedName)
}

// rename changes a key's name in the keychain.
func (c *Keychain) rename(oldName, newName string) {
	_, storedName, ok := c.lookupKey(oldName)
	if !ok {
		log.Fatalf("no such key %q", oldName)
	}
	if strings.IndexFunc(newName, unicode.IsSpace) >= 0 {
		log.Fatalf("name must not contain spaces")
	}
	// Check for name collision (exact match only — case-insensitive would be confusing).
	if _, _, exists := c.lookupKey(newName); exists {
		log.Fatalf("key %q already exists", newName)
	}

	var buf bytes.Buffer
	lines := bytes.SplitAfter(c.data, []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		trimmed := bytes.TrimSuffix(line, []byte("\n"))
		f := bytes.SplitN(trimmed, []byte(" "), 2)
		if len(f) >= 2 && string(f[0]) == storedName {
			fmt.Fprintf(&buf, "%s %s\n", newName, f[1])
		} else {
			buf.Write(line)
		}
	}

	c.data = buf.Bytes()
	c.keys = make(map[string]Key)
	c.parse(c.data)
	if err := c.writeFile(); err != nil {
		log.Fatalf("renaming key: %v", err)
	}
	log.Printf("renamed %q to %q", storedName, newName)
}

// validate checks every line in the keychain and reports any issues found.
func (c *Keychain) validate() {
	lines := bytes.SplitAfter(c.data, []byte("\n"))
	var issues []string
	seen := make(map[string]int) // name → first line number
	validKeys := 0

	for i, line := range lines {
		lineno := i + 1
		trimmed := bytes.TrimSuffix(line, []byte("\n"))

		// Skip blank lines.
		if len(trimmed) == 0 {
			continue
		}

		f := bytes.Split(trimmed, []byte(" "))

		if len(f) < 3 {
			issues = append(issues, fmt.Sprintf("line %d: too few fields (%d), need at least 3", lineno, len(f)))
			continue
		}

		// Check name is valid (no spaces already guaranteed by splitting, but check non-empty).
		name := string(f[0])
		if name == "" {
			issues = append(issues, fmt.Sprintf("line %d: empty key name", lineno))
			continue
		}

		// Check digit count.
		digitsField := string(f[1])
		if len(digitsField) != 1 || digitsField[0] < '6' || digitsField[0] > '8' {
			issues = append(issues, fmt.Sprintf("line %d: invalid digit count %q (must be 6, 7, or 8)", lineno, digitsField))
			continue
		}

		// Check secret is valid base32.
		secret := string(f[2])
		if _, err := decodeKey(secret); err != nil {
			issues = append(issues, fmt.Sprintf("line %d: invalid base32 secret %q: %v", lineno, secret, err))
			continue
		}

		// Check optional counter field.
		if len(f) == 4 {
			counterField := string(f[3])
			if len(counterField) != counterFieldWidth {
				issues = append(issues, fmt.Sprintf("line %d: counter field width is %d, expected %d", lineno, len(counterField), counterFieldWidth))
				continue
			}
			if _, err := strconv.ParseUint(counterField, 10, 64); err != nil {
				issues = append(issues, fmt.Sprintf("line %d: invalid counter value %q: %v", lineno, counterField, err))
				continue
			}
		} else if len(f) > 4 {
			issues = append(issues, fmt.Sprintf("line %d: too many fields (%d)", lineno, len(f)))
			continue
		}

		validKeys++

		// Check for duplicate key names.
		if firstLine, ok := seen[name]; ok {
			issues = append(issues, fmt.Sprintf("line %d: duplicate key name %q (also appears on line %d)", lineno, name, firstLine))
		} else {
			seen[name] = lineno
		}
	}

	if validKeys == 0 && len(issues) == 0 {
		fmt.Println("keychain is empty")
		return
	}

	if len(issues) == 0 {
		fmt.Printf("keychain is valid (%d key(s))\n", validKeys)
	} else {
		fmt.Printf("found %d issue(s) in %d line(s):\n\n", len(issues), len(lines))
		for _, issue := range issues {
			fmt.Println(issue)
		}
	}
}

// sortedKeyNames returns all key names sorted alphabetically.
func (c *Keychain) sortedKeyNames() []string {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
