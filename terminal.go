package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/jorgelbg/pinentry-touchid/sensor"
)

// Replace the process so all Assuan options, inquiries and responses are
// preserved, including ttyname supplied by gpg-agent after startup.
func execTerminalPinentry() error {
	path, err := exec.LookPath("pinentry-curses")
	if err != nil {
		return fmt.Errorf("terminal input selected; install pinentry-curses: %w", err)
	}
	return syscall.Exec(path, []string{path}, os.Environ())
}

// An empty reason selects graphical input. Environment values are never logged.
func terminalReason(force bool, console sensor.ConsoleState, getenv func(string) string) string {
	if force {
		return "-tty"
	}
	if getenv("PINENTRY_USER_DATA") == "pinentry-touchid:tty" {
		return "PINENTRY_USER_DATA requests terminal"
	}
	for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if getenv(name) != "" {
			return name + " indicates remote session"
		}
	}
	if !console.GUIAccess {
		return "no graphical access"
	}
	if !console.OnConsole {
		return "no active console session"
	}
	if !console.Unlocked {
		return "console locked or lock state unknown"
	}
	if !console.DisplayAwake {
		return "display asleep or display state unknown"
	}
	return ""
}
