// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// The keychain is stored in $HOME/.2fa. If the environment variable
// 2FA_PASS is set, the keychain file is encrypted with AES-256-GCM
// using a key derived from that passphrase (Argon2id KDF).
//
// See README.md for full documentation.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
)

// Keychain file format constants.
const (
	magicHeader       = "2FA!v1\n"
	saltLen           = 16
	nonceLen          = 12
	aesKeyLen         = 32 // AES-256
	argon2Time        = 3
	argon2Memory      = 64 * 1024
	argon2Threads     = 4
	counterFieldWidth = 20 // width of HOTP counter field in keychain file
)

// Version set by linker at build time (goreleaser: -X main.version={{ .Version }}).
var version = "dev"

// Cached encryption key derived from 2FA_PASS (set once).
var cachedKey []byte

func main() {
	app := &cli.App{
		Name:            "2fa",
		Usage:           "two-factor authentication agent",
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "hotp", Usage: "add key as HOTP (counter-based) key"},
			&cli.BoolFlag{Name: "7", Usage: "generate 7-digit code"},
			&cli.BoolFlag{Name: "8", Usage: "generate 8-digit code"},
		},
		Action: func(c *cli.Context) error {
			// No args → interactive menu (default).
			if c.NArg() == 0 {
				openKeychain().menu()
				return nil
			}
			// First arg is a key name → show code.
			return showByName(c.Args().First())
		},
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "list all key names",
				Action: func(c *cli.Context) error {
					openKeychain().list()
					return nil
				},
			},
			{
				Name:  "all",
				Usage: "print codes for all time-based keys",
				Action: func(c *cli.Context) error {
					openKeychain().showAll()
					return nil
				},
			},
			{
				Name:      "add",
				Usage:     "add a key (or an otpauth:// URI)",
				ArgsUsage: "<name | URI>",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "hotp", Usage: "counter-based key"},
					&cli.BoolFlag{Name: "7", Usage: "7-digit code"},
					&cli.BoolFlag{Name: "8", Usage: "8-digit code"},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return cli.Exit("usage: 2fa add [--hotp] [--7|--8] <name | URI>", 2)
					}
					arg := c.Args().First()

					// Detect otpauth:// URI import.
					if strings.HasPrefix(arg, "otpauth://") {
						name, secret, digits, hotp, err := parseOTPURI(arg)
						if err != nil {
							return cli.Exit(fmt.Sprintf("invalid URI: %v", err), 1)
						}
						openKeychain().insertKey(name, secret, digits, hotp)
						return nil
					}

					// Normal key add.
					if strings.IndexFunc(arg, unicode.IsSpace) >= 0 {
						return cli.Exit("name must not contain spaces", 1)
					}
					size := 6
					if c.Bool("7") {
						size = 7
						if c.Bool("8") {
							return cli.Exit("cannot use --7 and --8 together", 2)
						}
					} else if c.Bool("8") {
						size = 8
					}
					openKeychain().add(arg, size, c.Bool("hotp"))
					return nil
				},
			},
			{
				Name:  "export",
				Usage: "export keychain to stdout (decrypted)",
				Action: func(c *cli.Context) error {
					k := openKeychain()
					os.Stdout.Write(k.data)
					return nil
				},
			},
			{
				Name:  "import",
				Usage: "import keychain from stdin",
				Action: func(c *cli.Context) error {
					data, err := io.ReadAll(os.Stdin)
					if err != nil {
						return cli.Exit(fmt.Sprintf("reading input: %v", err), 1)
					}
					if len(bytes.TrimSpace(data)) == 0 {
						return cli.Exit("no data to import", 1)
					}
					k := &Keychain{
						file: keychainPath(),
						keys: make(map[string]Key),
					}
					if pass := os.Getenv("2FA_PASS"); pass != "" {
						k.encrypted = true
						k.passphrase = pass
					}
					k.data = data
					k.parse(data)
					if len(k.keys) == 0 {
						return cli.Exit("no valid keys found in input", 1)
					}
					if err := k.writeFile(); err != nil {
						return cli.Exit(fmt.Sprintf("importing keychain: %v", err), 1)
					}
					log.Printf("imported %d keys to %s", len(k.keys), filepath.Base(k.file))
					return nil
				},
			},
			{
				Name:      "delete",
				Usage:     "delete a key",
				ArgsUsage: "<name>",
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return cli.Exit("usage: 2fa delete <name>", 2)
					}
					openKeychain().remove(c.Args().First())
					return nil
				},
			},
			{
				Name:      "rename",
				Usage:     "rename a key",
				ArgsUsage: "<old-name> <new-name>",
				Action: func(c *cli.Context) error {
					if c.NArg() != 2 {
						return cli.Exit("usage: 2fa rename <old-name> <new-name>", 2)
					}
					openKeychain().rename(c.Args().Get(0), c.Args().Get(1))
					return nil
				},
			},
			{
				Name:  "validate",
				Usage: "check keychain file integrity",
				Action: func(c *cli.Context) error {
					openKeychain().validate()
					return nil
				},
			},
			{
				Name:  "version",
				Usage: "print version",
				Action: func(c *cli.Context) error {
					fmt.Printf("2fa %s\n", version)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func keychainPath() string {
	if e := os.Getenv("2FA_FILE"); e != "" {
		return e
	}
	return filepath.Join(os.Getenv("HOME"), ".2fa")
}

func openKeychain() *Keychain {
	return readKeychain(keychainPath())
}

func showByName(name string) error {
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return cli.Exit("name must not contain spaces", 1)
	}
	openKeychain().show(name)
	return nil
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

// ---------------------------------------------------------------------------
// Keychain
// ---------------------------------------------------------------------------

type Keychain struct {
	file       string
	data       []byte // raw file content (plaintext, after decryption if applicable)
	keys       map[string]Key
	encrypted  bool   // whether the file on disk is encrypted
	passphrase string // cached passphrase, empty = no encryption
}

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
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), c.file); err != nil {
		os.Remove(tmp.Name())
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
	c.parse([]byte(line))

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
		// HOTP: counter-based.
		n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterFieldWidth]), 10, 64)
		if err != nil {
			log.Fatalf("malformed key counter for %q (%q)", name, c.data[k.offset:k.offset+counterFieldWidth])
		}
		n++
		code = hotp(k.raw, n, k.digits)

		// Rebuild the entire keychain data with updated counter.
		newCounter := []byte(fmt.Sprintf("%0*d", counterFieldWidth, n))
		newData := make([]byte, len(c.data))
		copy(newData, c.data)
		copy(newData[k.offset:k.offset+counterFieldWidth], newCounter)

		c.data = newData
		// Re-parse so the offset is correct for future lookups.
		c.keys = make(map[string]Key)
		c.parse(c.data)

		if err := c.writeFile(); err != nil {
			log.Fatalf("updating keychain: %v", err)
		}
	} else {
		// Time-based key (TOTP) with ±1 window tolerance.
		now := time.Now()
		code = totp(k.raw, now, k.digits)
		if code == 0 {
			code = totp(k.raw, now.Add(-30*time.Second), k.digits)
		}
		if code == 0 {
			code = totp(k.raw, now.Add(30*time.Second), k.digits)
		}
	}
	return fmt.Sprintf("%0*d", k.digits, code)
}

func (c *Keychain) show(name string) {
	code := c.code(name)
	if err := clipboard.WriteAll(code); err != nil {
		log.Printf("warning: clipboard copy failed: %v", err)
	}
	clearClipboardAfter(30 * time.Second)
	fmt.Printf("%s\n", code)
}

func (c *Keychain) showAll() {
	names := c.sortedKeyNames()
	max := 0
	for _, name := range names {
		k := c.keys[name]
		if max < k.digits {
			max = k.digits
		}
	}
	for _, name := range names {
		k := c.keys[name]
		var code string
		if k.offset == 0 {
			// TOTP: compute live code with ±1 window tolerance.
			now := time.Now()
			try := totp(k.raw, now, k.digits)
			if try == 0 {
				try = totp(k.raw, now.Add(-30*time.Second), k.digits)
			}
			if try == 0 {
				try = totp(k.raw, now.Add(30*time.Second), k.digits)
			}
			code = fmt.Sprintf("%0*d", k.digits, try)
		} else {
			// HOTP: cannot show without consuming the counter.
			code = strings.Repeat("-", k.digits)
		}
		fmt.Printf("%-*s\t%s\n", max, code, name)
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

// ---------------------------------------------------------------------------
// TUI menu
// ---------------------------------------------------------------------------

var menuSelectedStyle = lipgloss.NewStyle().
	Background(lipgloss.Color("#7C3AED")). // purple bg
	Foreground(lipgloss.Color("#FFFFFF"))

// menuKeyInfo stores the data needed to render a key in the TUI menu.
type menuKeyInfo struct {
	digits int
	raw    []byte
	isHOTP bool
}

// menuModel is the bubbletea state for the interactive key picker.
type menuModel struct {
	names  []string
	keyInf map[string]menuKeyInfo
	cursor int
	chosen string
	filter []rune
	width  int
	height int
}

// tickMsg is sent every second to trigger a re-render for the countdown.
type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m menuModel) Init() tea.Cmd { return tickCmd() }

func (m menuModel) visible() []string {
	if len(m.filter) == 0 {
		return m.names
	}
	q := strings.ToLower(string(m.filter))
	var f []string
	for _, n := range m.names {
		if strings.Contains(strings.ToLower(n), q) {
			f = append(f, n)
		}
	}
	return f
}

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tickMsg:
		// Re-render with updated countdown.
		return m, tickCmd()
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "enter":
			v := m.visible()
			if len(v) > 0 && m.cursor < len(v) {
				m.chosen = v[m.cursor]
			}
			return m, tea.Quit
		case "up", "k":
			v := m.visible()
			if m.cursor > 0 {
				m.cursor--
			} else if len(v) > 0 {
				m.cursor = len(v) - 1
			}
		case "down", "j":
			v := m.visible()
			if m.cursor < len(v)-1 {
				m.cursor++
			} else {
				m.cursor = 0
			}
		case "backspace":
			if len(m.filter) > 0 {
				m.filter = m.filter[:len(m.filter)-1]
				m.cursor = 0
			}
		default:
			if r := rune(msg.String()[0]); unicode.IsPrint(r) {
				m.filter = append(m.filter, r)
				m.cursor = 0
			}
		}
	}
	return m, nil
}

func (m menuModel) View() string {
	var b strings.Builder
	b.WriteString(" 2FA keys\n\n")

	visible := m.visible()

	if m.cursor >= len(visible) && len(visible) > 0 {
		m.cursor = len(visible) - 1
	}

	maxItems := m.height - 4
	if maxItems <= 0 {
		maxItems = 20
	}
	if maxItems > len(visible) {
		maxItems = len(visible)
	}

	// Compute remaining seconds for the current TOTP window.
	remaining := 30 - (time.Now().Unix() % 30)

	scrollOff := 0
	if m.cursor >= maxItems {
		scrollOff = m.cursor - maxItems/2
		if scrollOff+maxItems > len(visible) {
			scrollOff = len(visible) - maxItems
		}
	}

	for i := 0; i < maxItems; i++ {
		idx := scrollOff + i
		if idx >= len(visible) {
			break
		}
		name := visible[idx]
		info := m.keyInf[name]

		// Build status suffix: countdown for TOTP, "HOTP" label for HOTP.
		var suffix string
		if info.isHOTP {
			suffix = " [HOTP]"
		} else {
			suffix = fmt.Sprintf(" [%ds]", remaining)
		}

		line := fmt.Sprintf("  %s%s", name, suffix)
		if idx == m.cursor {
			w := m.width
			if w <= 0 {
				w = 80
			}
			b.WriteString(menuSelectedStyle.Width(w).Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}

	b.WriteString("\n ")
	if len(m.filter) > 0 {
		b.WriteString(string(m.filter))
	} else {
		b.WriteString("type to filter…")
	}
	b.WriteRune('▋')

	return b.String()
}

func (c *Keychain) menu() {
	if len(c.keys) == 0 {
		log.Fatal("no keys in keychain")
	}

	names := c.sortedKeyNames()
	keyInf := make(map[string]menuKeyInfo, len(c.keys))
	for name, k := range c.keys {
		keyInf[name] = menuKeyInfo{
			digits: k.digits,
			raw:    k.raw,
			isHOTP: k.offset != 0,
		}
	}

	p := tea.NewProgram(menuModel{
		names:  names,
		keyInf: keyInf,
		cursor: 0,
		filter: nil,
		width:  80,
		height: 24,
	})
	result, err := p.Run()
	if err != nil {
		log.Fatalf("menu error: %v", err)
	}

	m := result.(menuModel)
	if m.chosen == "" {
		os.Exit(1)
	}

	showWithClip(m.chosen)
}

func showWithClip(name string) {
	k := openKeychain()
	code := k.code(name)
	if err := clipboard.WriteAll(code); err != nil {
		log.Printf("warning: clipboard copy failed: %v", err)
	}
	clearClipboardAfter(30 * time.Second)
	fmt.Printf("%s\n", code)
}

// ---------------------------------------------------------------------------
// Cryptographic helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Encryption / decryption (AES-256-GCM + Argon2id KDF)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Clipboard auto-clear
// ---------------------------------------------------------------------------

func clearClipboardAfter(d time.Duration) {
	time.AfterFunc(d, func() {
		if err := clipboard.WriteAll(""); err != nil {
			log.Printf("warning: could not clear clipboard: %v", err)
		}
	})
}
