// Copyright 2026 Phil Harris. All rights reserved.
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package app

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestMenuView_ContainsKeyNames(t *testing.T) {
	m := menuModel{
		names: []string{"github", "gitlab"},
		keyInf: map[string]menuKeyInfo{
			"github": {digits: 6, raw: []byte("key"), isHOTP: false},
			"gitlab": {digits: 6, raw: []byte("key"), isHOTP: true},
		},
		cursor: 0,
		filter: nil,
		width:  80,
		height: 24,
	}
	out := m.View()
	if !strings.Contains(out, "github") {
		t.Error("View should contain 'github'")
	}
	if !strings.Contains(out, "gitlab") {
		t.Error("View should contain 'gitlab'")
	}
	if !strings.Contains(out, "[HOTP]") {
		t.Error("View should show [HOTP] for HOTP keys")
	}
}

func TestMenuUpdate_WindowSize(t *testing.T) {
	m := menuModel{width: 80, height: 24}
	msg := tea.WindowSizeMsg{Width: 120, Height: 40}
	result, _ := m.Update(msg)
	updated := result.(menuModel)
	if updated.width != 120 || updated.height != 40 {
		t.Errorf("expected 120x40, got %dx%d", updated.width, updated.height)
	}
}

func TestMenuUpdate_ArrowKeys(t *testing.T) {
	m := menuModel{
		names:  []string{"a", "b", "c"},
		keyInf: map[string]menuKeyInfo{"a": {}, "b": {}, "c": {}},
		cursor: 0,
	}
	// Down moves to 1.
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m1 := result.(menuModel)
	if m1.cursor != 1 {
		t.Errorf("down: cursor should be 1, got %d", m1.cursor)
	}
	// Up moves back to 0.
	result, _ = m1.Update(tea.KeyMsg{Type: tea.KeyUp})
	m2 := result.(menuModel)
	if m2.cursor != 0 {
		t.Errorf("up: cursor should be 0, got %d", m2.cursor)
	}
}

func TestMenuUpdate_Select(t *testing.T) {
	m := menuModel{
		names:  []string{"github"},
		keyInf: map[string]menuKeyInfo{"github": {}},
		cursor: 0,
	}
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	selected := result.(menuModel)
	if selected.chosen != "github" {
		t.Errorf("expected 'github', got %q", selected.chosen)
	}
}

func TestMenuVisible_WithFilter(t *testing.T) {
	m := menuModel{
		names:  []string{"github", "gitlab", "bitbucket"},
		keyInf: map[string]menuKeyInfo{"github": {}, "gitlab": {}, "bitbucket": {}},
		filter: []rune("git"),
	}
	visible := m.visible()
	if len(visible) != 2 {
		t.Errorf("expected 2 visible with filter 'git', got %d: %v", len(visible), visible)
	}
	if visible[0] != "github" || visible[1] != "gitlab" {
		t.Errorf("expected [github gitlab], got %v", visible)
	}
}

func TestMenuVisible_WithFilterCaseInsensitive(t *testing.T) {
	m := menuModel{
		names:  []string{"GitHub", "GITLAB"},
		keyInf: map[string]menuKeyInfo{"GitHub": {}, "GITLAB": {}},
		filter: []rune("git"),
	}
	visible := m.visible()
	if len(visible) != 2 {
		t.Errorf("expected 2 visible with case-insensitive filter 'git', got %d: %v", len(visible), visible)
	}
}

func TestMenuVisible_NoFilter(t *testing.T) {
	m := menuModel{
		names:  []string{"github", "gitlab"},
		keyInf: map[string]menuKeyInfo{"github": {}, "gitlab": {}},
	}
	visible := m.visible()
	if len(visible) != 2 {
		t.Errorf("expected 2 visible with no filter, got %d", len(visible))
	}
}

func TestMenuUpdate_FilterTyping(t *testing.T) {
	m := menuModel{
		names:  []string{"alpha", "beta", "gamma"},
		keyInf: map[string]menuKeyInfo{"alpha": {}, "beta": {}, "gamma": {}},
	}
	// Type 'a'.
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	m1 := result.(menuModel)
	if string(m1.filter) != "a" {
		t.Errorf("filter should be 'a', got %q", string(m1.filter))
	}
	if m1.cursor != 0 {
		t.Errorf("cursor should reset to 0 on filter, got %d", m1.cursor)
	}
}

func TestMenuUpdate_Backspace(t *testing.T) {
	m := menuModel{
		names:  []string{"github"},
		keyInf: map[string]menuKeyInfo{"github": {}},
		filter: []rune("gi"),
	}
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m1 := result.(menuModel)
	if string(m1.filter) != "g" {
		t.Errorf("filter should be 'g' after backspace, got %q", string(m1.filter))
	}
}

func TestMenuUpdate_Quit(t *testing.T) {
	m := menuModel{names: []string{"a"}, keyInf: map[string]menuKeyInfo{"a": {}}}
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Error("expected quit command on esc")
	}
}
