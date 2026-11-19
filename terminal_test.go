package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jorgelbg/pinentry-touchid/sensor"
)

// A subprocess is required because successful fallback replaces this process.
func TestTerminalExec(t *testing.T) {
	if os.Getenv("PINENTRY_TEST_EXEC") == "1" {
		if err := execTerminalPinentry(); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pinentry-curses"), []byte("#!/bin/sh\nexec /bin/cat\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTerminalExec$")
	cmd.Env = append(os.Environ(), "PINENTRY_TEST_EXEC=1", "PATH="+dir)
	protocol := "OPTION ttyname=/dev/ttys001\nGETINFO version\nBYE\n"
	cmd.Stdin = strings.NewReader(protocol)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fallback failed: %v: %s", err, out)
	}
	if string(out) != protocol {
		t.Fatalf("protocol changed: %q", out)
	}
}

func TestTerminalMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if err := execTerminalPinentry(); err == nil || !strings.Contains(err.Error(), "install pinentry-curses") {
		t.Fatalf("expected actionable missing-terminal error, got %v", err)
	}
}

// Exercise the real self-test exit status with no graphical dependencies on PATH.
func TestTerminalSelfTest(t *testing.T) {
	if os.Getenv("PINENTRY_TEST_SELF_TEST") == "1" {
		*terminal = true
		*selfTest = true
		DefaultLogLocation = filepath.Join(os.Getenv("PATH"), "missing-dir", "log")
		main()
		return
	}
	for _, installed := range []bool{false, true} {
		name := "missing"
		if installed {
			name = "installed"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if installed {
				if err := os.WriteFile(filepath.Join(dir, "pinentry-curses"), []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestTerminalSelfTest$")
			cmd.Env = append(os.Environ(), "PINENTRY_TEST_SELF_TEST=1", "PATH="+dir)
			out, err := cmd.CombinedOutput()
			if installed && err != nil {
				t.Fatalf("installed terminal rejected: %v: %s", err, out)
			}
			if !installed {
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 {
					t.Fatalf("missing terminal should exit 1: %v: %s", err, out)
				}
			}
			if !strings.Contains(string(out), "Input:      terminal") || !strings.Contains(string(out), "Terminal:") {
				t.Fatalf("missing terminal diagnostics: %s", out)
			}
			for _, unwanted := range []string{"Touch ID:", "Fallback:", "Log file:"} {
				if strings.Contains(string(out), unwanted) {
					t.Fatalf("terminal self-test checked GUI dependency: %s", out)
				}
			}
		})
	}
}

func TestTerminalReason(t *testing.T) {
	awake := sensor.ConsoleState{GUIAccess: true, OnConsole: true, Unlocked: true, DisplayAwake: true}
	for _, tc := range []struct {
		name  string
		force bool
		state sensor.ConsoleState
		env   map[string]string
		want  string
	}{
		{"local", false, awake, nil, ""},
		{"local Rex retains graphical input", false, awake, map[string]string{"REX_SESSION": "session:local", "REX_BLOCK": "block:local", "REX_SERVER": "unix:///tmp/rex.sock"}, ""},
		{"forced", true, awake, nil, "-tty"},
		{"remote unlocked screen sharing", false, awake, map[string]string{"SSH_CONNECTION": "remote"}, "SSH_CONNECTION indicates remote session"},
		{"remote client", false, awake, map[string]string{"SSH_CLIENT": "remote"}, "SSH_CLIENT indicates remote session"},
		{"remote tty", false, awake, map[string]string{"SSH_TTY": "/dev/ttys001"}, "SSH_TTY indicates remote session"},
		{"agent request override", false, awake, map[string]string{"PINENTRY_USER_DATA": "pinentry-touchid:tty"}, "PINENTRY_USER_DATA requests terminal"},
		{"unrelated user data", false, awake, map[string]string{"PINENTRY_USER_DATA": "other"}, ""},
		{"locked", false, sensor.ConsoleState{GUIAccess: true, OnConsole: true, DisplayAwake: true}, nil, "console locked or lock state unknown"},
		{"asleep", false, sensor.ConsoleState{GUIAccess: true, OnConsole: true, Unlocked: true}, nil, "display asleep or display state unknown"},
		{"inactive", false, sensor.ConsoleState{GUIAccess: true, Unlocked: true, DisplayAwake: true}, nil, "no active console session"},
		{"unknown", false, sensor.ConsoleState{}, nil, "no graphical access"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := terminalReason(tc.force, tc.state, func(k string) string { return tc.env[k] })
			if got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}
