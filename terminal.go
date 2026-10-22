package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
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
