// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"unicode"

	"github.com/urfave/cli/v2"
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

// Version set by linker at build time (goreleaser: -X github.com/pharrisee/2fa/internal/app.Version={{ .Version }}).
// Falls back to runtime/debug build info when unset.
var Version = "dev"

func appVersion() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		v := info.Main.Version
		if v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

// Cached encryption key derived from 2FA_PASS (set once).
var cachedKey []byte

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

// Run is the application entry point.
func Run() {
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
					fmt.Printf("2fa %s\n", appVersion())
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
