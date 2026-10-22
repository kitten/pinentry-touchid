package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTerminalSelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		force, gui bool
		env        map[string]string
		want       bool
	}{
		{"desktop", false, true, nil, false},
		{"headless", false, false, nil, true},
		{"ssh", false, true, map[string]string{"SSH_CONNECTION": "client server"}, true},
		{"ssh tty", false, true, map[string]string{"SSH_TTY": "/dev/ttys001"}, true},
		{"forced", true, true, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := useTerminalPinentry(tc.force, tc.gui, func(k string) string { return tc.env[k] }); got != tc.want {
				t.Fatalf("terminal selection = %v, want %v", got, tc.want)
			}
		})
	}
}

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
