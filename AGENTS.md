# AGENTS.md — Operating Manual

This file is part of the [shared-brain](https://github.com/Jason-Cyr/ai-shared-brain)
persistent memory system. It tells AI agents how to work on this project.

---

## Project Identity

- **Name:** 2fa
- **Role:** Zero-frills TOTP/HOTP authenticator — a single Go binary
- **Repository:** `github.com/pharrisee/2fa`
- **Language:** Go 1.26.3
- **Keychain file:** `~/.2fa` (plaintext by default, AES-256-GCM with `2FA_PASS`)

---

## Startup Ritual

Every session, read these files first:

1. `README.md` — full docs, commands, architecture
2. `main.go` — the entire program (~560 lines, single package)
3. `go.mod` — dependencies

The entire program is one file (`main.go`). Tests live in `main_test.go`
(41 tests covering TOTP/HOTP RFC vectors, parsing, encryption round-trip,
case-insensitive lookup, file I/O, and export).

Build and install: `./install.sh` (builds to `~/.local/bin/2fa`).
CI/CD in `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
GoReleaser config in `.goreleaser.yaml`.

---

## Key Principles

1. **Minimalism.** Everything fits in one file. Adding a dependency requires
   strong justification. Prefer stdlib over external packages.

2. **Backward compatibility.** The `~/.2fa` file format must never break.
   Encrypted files use a magic header; unencrypted files have none.
   Both must parse correctly forever.

3. **Clipboard is the default.** `2fa <name>` always copies to clipboard —
   no `-clip` flag needed.

4. **Case-insensitive lookup.** Key names are case-insensitive on lookup
   (`2fa github` matches `GitHub`). If two keys differ only by case,
   error with an unambiguous message.

5. **Security defaults.** File permission warnings, encrypted storage opt-in —
   all default-on protections.

---

## Code Conventions

- Single `package main`, single `main.go`
- No test files (none exist, don't create them unless asked)
- Error messages prefixed with `"2fa: "` via `log.SetPrefix`
- `log.Fatal` for unrecoverable errors (CLI tool, no daemon)
- Tabs for indentation (standard Go)

## TUI Menu (default with no args)

- `2fa` with no arguments opens the interactive menu (default mode)
- `2fa all` prints all codes side-by-side (for scripting)
- Implemented as a custom `bubbletea` model (`menuModel`) — not `huh` or `bubbles/list`
- Real-time filtering by typing, arrow keys move highlight, Enter selects
- Background color (`#7C3AED` purple) for the selected row, padded to terminal width
- The `menuModel.View()` method handles scrolling when items exceed viewport
- **Live countdown:** TOTP keys show remaining seconds (`[18s]`), updated every second
  via a `tickMsg`/`tickCmd` loop. HOTP keys show `[HOTP]` instead.
- The model stores a `keyInf map[string]menuKeyInfo` to render the countdown/HOTP label
  without re-parsing the keychain.

## Delete / Rename (`delete` / `rename`)

- `2fa delete <name>` — case-insensitive lookup, removes the line from `c.data`
  by iterating through lines with `bytes.SplitAfter` and rebuilding.
- `2fa rename <old> <new>` — same approach, replaces just the name prefix in the line.
- Both validate name collisions and space-in-name rules.
- These are the only ways to remove/rename keys (no manual file editing needed anymore).

## OTP URI Import

- `2fa add "otpauth://totp/..."` auto-detects the URI prefix, parses with `net/url`.
- Extracts: type (totp/hotp), secret, digits (default 6), name (from `issuer` query
  param or label component before `:`).
- Calls `insertKey()` directly — no stdin prompt.
- Zero new dependencies — `net/url` is stdlib.

## Helpers

- `sortedKeyNames()` — extracted helper used by `list()`, `showAll()`, `menu()`.
- `insertKey()` — extracted from `add()` so both stdin and URI paths share the same
  file-append-and-write logic.
- `parseOTPURI()` — parses an `otpauth://` URI into its components.

## Validate (`validate`)

- `2fa validate` opens the keychain and independently re-parses every line.
- Checks: field count ≥3, digit count ∈ {6,7,8}, base32 decode succeeds,
  counter field width == 20 and parseable as uint64, duplicate key names.
- Reports all issues found, or "keychain is valid (N key(s))" / "keychain is empty".
- Does NOT modify the file — read-only inspection.

## Version (`version`)

- `2fa version` prints the version string.
- Default at dev builds: `"dev"`.
- Overridden at release by goreleaser ldflag: `-X main.version={{ .Version }}`.
- Package-level var `var version = "dev"`.

## Export / Import (`export` / `import`)

- `2fa export` reads the keychain (handles decryption) and writes `c.data` to stdout
- `2fa import` reads stdin, validates by parsing, then writes via `writeFile()`
  (which handles re-encryption if `2FA_PASS` is set on the destination)
- Export always outputs plaintext; import re-encrypts if needed
- The output format is raw keychain lines — no header, no metadata
- Used for migrating between machines or backup/restore

## Encryption Layer

- `encryptData` / `decryptData` — callers in `readKeychain` and `writeFile`
- Format: `2FA!v1\n` + base64(`salt(16) || nonce(12) || ciphertext`)
- Key derivation: Argon2id (time=3, mem=64MB, threads=4) → AES-256 key
- Cached in `cachedKey` package var to avoid re-derivation per-invocation
- `deriveKey` caches the derived key; invalidate if salt changes (currently salt is
  always fresh per encrypt, so cachedKey is only hit for decrypt-then-encrypt flows)

## Known Quirks

- HOTP counter updates rewrite the entire file (no in-place `WriteAt` when encrypted)
- `showAll()` skips HOTP keys — they show `---` instead of a code
- No file locking — concurrent writes from parallel invocations could corrupt
  the keychain (rare, but document it)
- The `-7` and `-8` flags are mutually exclusive (validated at runtime)

---

## Common Tasks

### Add a new flag

1. Add a `flag.Bool` or `flag.String` var near the others in the `var` block
2. Handle it in `main()` before the existing dispatch logic
3. Update `usage()`
4. Never remove existing flags without checking they aren't used

### Change the TUI menu

Edit `menuModel` struct, its `Update` and `View` methods. The model is ~100 lines
and lives entirely in `main.go`. No separate files.

### Add a new dependency

Run `go get <pkg>` then `go mod tidy`. Update the dependency table in README.md.
Only add if stdlib can't do the job.
