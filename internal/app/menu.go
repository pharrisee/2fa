// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

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
			fmt.Fprintf(&b, "%s\n", menuSelectedStyle.Width(w).Render(line))
		} else {
			fmt.Fprintf(&b, "%s\n", line)
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

	code := c.code(m.chosen)
	c.incrementCounter(m.chosen)
	if err := writeClipboard(code); err != nil {
		log.Printf("warning: clipboard copy failed: %v", err)
	}
	fmt.Printf("%s\n", code)
}
