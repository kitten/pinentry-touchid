// Copyright (c) 2021 Jorge Luis Betancourt. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/foxcpp/go-assuan/common"
	"github.com/foxcpp/go-assuan/pinentry"
	"github.com/keybase/go-keychain"
)

const (
	testPassword = "toomanysecrets2"
	keyDesc      = `Please enter the passphrase to unlock the OpenPGP secret key:
"Firstname Lastname <test@email.com>"
2048-bit RSA key, ID 61AF059BD632F971,
created 2021-01-01 (main key ID 70D56DF4CA30DE16).
`
	keyInfo = "n/8043823CBC5C5A0C66866520F333076D"
)

var dummyPrompt = func(s pinentry.Settings) ([]byte, error) { return []byte{}, nil }

func TestStoreEntryInKeychain(t *testing.T) {
	err := storePasswordInKeychain("sampleLabel", "keyInfo", []byte(testPassword), log.New(io.Discard, "", 0))

	if err != nil {
		t.Fatalf("storing entry in the Keychain should succeed: %s", err)
	}
}

func TestGetPasswordFromKeychain(t *testing.T) {
	defer func() {
		err := cleanKeychain("sampleLabel")

		if err != nil {
			t.Fatalf("failed to clear entry from Keychain: %s", err)
		}
	}()

	pass, _, err := passwordFromKeychain("sampleLabel", "", "")

	if err != nil {
		t.Fatalf("fetch entry from Keychain should succeed: %s", err)
	}

	if pass != testPassword {
		t.Fatalf("password mismatch got: %s want: %s", pass, testPassword)
	}
}

func TestGetPINReadsBiometricEntry(t *testing.T) {
	keychainLabel := `Firstname Lastname <test@email.com> (61AF059BD632F971)`
	defer func() { _ = cleanKeychain(keychainLabel) }()

	params := pinentry.Settings{
		Desc:    keyDesc,
		KeyInfo: keyInfo,
	}

	logger := log.New(io.Discard, "", 0)
	err := storePasswordInKeychain(keychainLabel, keyInfo, []byte(testPassword), logger)
	if err != nil {
		t.Fatalf("failed precreating entry in the Keychain: %s", err)
	}

	fn := GetPIN(dummyPrompt, logger)
	pass, pinErr := fn(params)

	if pinErr != nil {
		t.Fatalf("call to GetPIN should succeed: %s", err)
	}

	if pass != testPassword {
		t.Fatalf("password mismatch got: %s want: %s", pass, testPassword)
	}
}

func TestEntryNotInKeychain(t *testing.T) {
	keychainLabel := `Firstname Lastname <test@email.com> (61AF059BD632F971)`
	defer func() { _ = cleanKeychain(keychainLabel) }()

	logger := log.New(io.Discard, "", 0)
	params := pinentry.Settings{
		Desc:    keyDesc,
		KeyInfo: keyInfo,
	}

	// initially the entry for the test key is not in the keychain
	if pass, _, err := passwordFromKeychain(keychainLabel, "", ""); err == nil || pass != "" {
		t.Fatalf("unexpected entry found in the keychain: %s", keychainLabel)
	}

	fallBack := false
	validPinFn := func(s pinentry.Settings) ([]byte, error) {
		fallBack = true
		return []byte(testPassword), nil
	}
	fn := GetPIN(validPinFn, logger)
	pass, pinErr := fn(params)
	if pinErr != nil {
		t.Fatalf("call to GetPIN should succeed: %s", pinErr)
	}

	if !fallBack {
		t.Fatalf("the fallback password prompt should have been called")
	}

	if pass != testPassword {
		t.Fatalf("password mismatch got: %s want: %s", pass, testPassword)
	}

	// after the successful run of GetPIN the entry should be present in the keychain
	if pass, _, err := passwordFromKeychain(keychainLabel, "", ""); err != nil || pass == "" {
		t.Fatalf("missing entry from the keychain: %s", keychainLabel)
	}
}

func TestConfirmShowsDialogWithoutPIN(t *testing.T) {
	promptCalled := false
	var gotCmd, gotDesc string
	c := KeychainClient{
		logger: log.New(io.Discard, "", 0),
		promptFn: func(pinentry.Settings) ([]byte, error) {
			promptCalled = true
			return nil, nil
		},
		dialogFn: func(cmd string, s pinentry.Settings) *common.Error {
			gotCmd, gotDesc = cmd, s.Desc
			return nil
		},
	}

	ok, err := c.Confirm(pinentry.Settings{Desc: "Please insert the card"})
	if err != nil || !ok {
		t.Fatalf("Confirm should succeed, got ok=%v err=%v", ok, err)
	}
	if promptCalled {
		t.Fatal("Confirm must not ask for a PIN")
	}
	if gotCmd != "CONFIRM" || gotDesc != "Please insert the card" {
		t.Fatalf("unexpected dialog: cmd=%q desc=%q", gotCmd, gotDesc)
	}
}

func TestConfirmPassesErrorThrough(t *testing.T) {
	want := &common.Error{Src: common.ErrSrcPinentry, Code: common.ErrCanceled, SrcName: "pinentry", Message: "canceled"}
	c := KeychainClient{
		logger:   log.New(io.Discard, "", 0),
		dialogFn: func(string, pinentry.Settings) *common.Error { return want },
	}

	ok, err := c.Confirm(pinentry.Settings{})
	if ok || err != want {
		t.Fatalf("got ok=%v err=%v, want false and %v", ok, err, want)
	}
}

func TestMsgShowsMessage(t *testing.T) {
	var gotCmd string
	c := KeychainClient{
		logger: log.New(io.Discard, "", 0),
		dialogFn: func(cmd string, _ pinentry.Settings) *common.Error {
			gotCmd = cmd
			return nil
		},
	}

	if err := c.Msg(pinentry.Settings{}); err != nil {
		t.Fatalf("Msg should succeed: %v", err)
	}
	if gotCmd != "MESSAGE" {
		t.Fatalf("got %q, want MESSAGE", gotCmd)
	}
}

// fakePinentry puts a fake gpgconf and pinentry on PATH. The pinentry logs
// every command and answers ERR to the commands listed in fail.
func fakePinentry(t *testing.T, fail string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	scripts := map[string]string{
		"gpgconf": "#!/bin/sh\necho 'pinentry:Passphrase Entry:" + filepath.Join(dir, "pinentry") + "'\n",
		"pinentry": "#!/bin/sh\necho 'OK hi'\n" +
			"while IFS= read -r l; do printf '%s\\n' \"$l\" >> '" + logPath + "'\n" +
			"case \"${l%% *}\" in " + fail + ") echo 'ERR 83886179 Operation cancelled <Pinentry>';;\n" +
			"BYE) echo OK; exit 0;; *) echo OK;; esac; done\n",
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	t.Cleanup(func() { os.Setenv("PATH", oldPath) })
	return logPath
}

func TestPinentryDialogSendsConfirm(t *testing.T) {
	logPath := fakePinentry(t, "NONE")

	err := pinentryDialog("CONFIRM", pinentry.Settings{Desc: "Please insert the card", OkBtn: "_OK", Timeout: 30})
	if err != nil {
		t.Fatalf("pinentryDialog should succeed: %v", err)
	}

	got, rerr := os.ReadFile(logPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	cmds := string(got)
	for _, want := range []string{"SETDESC Please insert the card\n", "SETOK _OK\n", "SETTIMEOUT 30\n", "CONFIRM\n"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("missing %q in:\n%s", want, cmds)
		}
	}
	for _, unwanted := range []string{"GETPIN", "SETREPEAT", "SETNOTOK"} {
		if strings.Contains(cmds, unwanted) {
			t.Errorf("unexpected %q in:\n%s", unwanted, cmds)
		}
	}
}

func TestPinentryDialogKeepsPinentryError(t *testing.T) {
	fakePinentry(t, "CONFIRM")

	err := pinentryDialog("CONFIRM", pinentry.Settings{Desc: "x"})
	if err == nil {
		t.Fatal("pinentryDialog should fail when pinentry cancels")
	}
	if err.Code != common.ErrCanceled {
		t.Fatalf("got code %d, want %d", err.Code, common.ErrCanceled)
	}
}

// Removes a matching entry from the "main" keychain.
// Since the item gets added in the same process, i.e temporal build while executing the test, it
// shouldn't request the password from the user.
func cleanKeychain(label string) error {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetLabel(label)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	return keychain.DeleteItem(query)
}

func TestWithLoggerDoesNotPanic(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	client := WithLogger(logger)
	if client.logger == nil {
		t.Fatal("expected logger to be set")
	}
}

func TestNewGracefulLogFileHandling(t *testing.T) {
	// Save and restore DefaultLogLocation
	origLocation := DefaultLogLocation
	defer func() { DefaultLogLocation = origLocation }()

	// Point to an unwritable path
	dir := t.TempDir()
	unwritable := filepath.Join(dir, "noperm")
	if err := os.Mkdir(unwritable, 0000); err != nil {
		t.Fatalf("failed to create unwritable dir: %v", err)
	}
	DefaultLogLocation = filepath.Join(unwritable, "test.log")

	// New() should not panic — it should fall back to stderr
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New() panicked when log file is unwritable: %v", r)
		}
	}()

	client := New()
	if client.logger == nil {
		t.Fatal("expected logger to be set even with unwritable log path")
	}
}

func TestGetInfoHandler(t *testing.T) {
	tests := []struct {
		name      string
		params    string
		wantData  string
		wantError bool
		errorCode int
	}{
		{
			name:      "flavor",
			params:    "flavor",
			wantData:  "touchid",
			wantError: false,
		},
		{
			name:      "version",
			params:    "version", 
			wantData:  version,
			wantError: false,
		},
		{
			name:      "pid",
			params:    "pid",
			wantData:  strconv.Itoa(os.Getpid()),
			wantError: false,
		},
		{
			name:      "ttyinfo",
			params:    "ttyinfo",
			wantData:  strings.TrimSpace(os.Getenv("GPG_TTY") + " " + strconv.Itoa(os.Getppid()) + " " + os.Getenv("TERM")),
			wantError: false,
		},
		{
			name:      "unknown",
			params:    "unknown",
			wantError: true,
			errorCode: int(common.ErrNotFound),
		},
		{
			name:      "empty",
			params:    "",
			wantError: true,
			errorCode: int(common.ErrAssInvValue),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := getInfoHandler(&buf, nil, tt.params)

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if int(err.Code) != tt.errorCode {
					t.Errorf("expected error code %d but got %d", tt.errorCode, int(err.Code))
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				
				// Check that data was written
				output := buf.String()
				if !strings.Contains(output, tt.wantData) {
					t.Errorf("expected output to contain %q but got %q", tt.wantData, output)
				}
			}
		})
	}
}
