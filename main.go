// Copyright (c) 2021 Jorge Luis Betancourt. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.
//
//go:build darwin && cgo
// +build darwin,cgo

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/enescakir/emoji"
	"github.com/foxcpp/go-assuan/common"
	"github.com/foxcpp/go-assuan/pinentry"
	"github.com/foxcpp/go-assuan/server"
	pinentryBinary "github.com/gopasspw/pinentry"
	"github.com/jorgelbg/pinentry-touchid/sensor"
)

// PromptFunc is a function that asks a password from the user
type PromptFunc func(pinentry.Settings) ([]byte, error)

// GetPinFunc is a function that executes the process for getting a password from the Keychain
type GetPinFunc func(pinentry.Settings) (string, *common.Error)

const (
	// DefaultLogFilename default name for the log files
	DefaultLogFilename = "pinentry-touchid.log"
	defaultLoggerFlags = log.Ldate | log.Ltime | log.Lshortfile
)

// version is filled by -ldflags "-X main.version=$(git describe --tags)"
var version = "devel"

var (
	// DefaultLogLocation is the location of the log file
	DefaultLogLocation = filepath.Join(filepath.Clean(os.TempDir()), DefaultLogFilename)

	emailRegex    = regexp.MustCompile(`\"(?P<name>.*<(?P<email>.*)>)\"`)
	keyIDRegex    = regexp.MustCompile(`ID (?P<keyId>.*),`) // keyID should be of exactly 8 or 16 characters
	sshKeyIDRegex = regexp.MustCompile(`SHA256:(?P<keyId>.*)`)

	errEmptyResults    = errors.New("no matching entry was found")
	errMultipleMatches = errors.New("multiple entries matched the query")

	check      = flag.Bool("check", false, "Verify that pinentry-mac is present in the system.")
	fixSymlink = flag.Bool("fix", false, "Set up pinentry-mac as the fallback PIN entry program.")
	selfTest   = flag.Bool("self-test", false, "Run startup diagnostics and report status.")
	_          = flag.String("display", "", "Set the X display (unused)")
)

const (
	expectedKeyLengthGPG     = 8
	expectedKeyLengthFullGPG = 16
	expectedKeyLengthSSH     = 43
)

// KeychainClient represents a single instance of a pinentry server
type KeychainClient struct {
	logger   *log.Logger
	promptFn PromptFunc
}

// New returns a new instance of KeychainClient with a configured logger and
// pinentry-mac as the fallback PIN prompt.
func New() KeychainClient {
	var logger *log.Logger
	path := filepath.Clean(DefaultLogLocation)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		file, err := os.Create(path)
		if err != nil {
			logger = log.New(os.Stderr, "pinentry-touchid: ", defaultLoggerFlags)
			logger.Printf("Warning: could not create log file %s: %v, logging to stderr", path, err)
		} else {
			logger = log.New(file, "", defaultLoggerFlags)
		}
	} else {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			logger = log.New(os.Stderr, "pinentry-touchid: ", defaultLoggerFlags)
			logger.Printf("Warning: could not open log file %s: %v, logging to stderr", path, err)
		} else {
			logger = log.New(file, "", defaultLoggerFlags)
		}
	}

	logger.Print("Ready!")

	return KeychainClient{
		logger:   logger,
		promptFn: passwordPrompt,
	}
}

// WithLogger allows to create a new instance of KeychainClient with a custom logger
func WithLogger(logger *log.Logger) KeychainClient {
	return KeychainClient{
		logger:   logger,
		promptFn: passwordPrompt,
	}
}

// passwordFromKeychain retrieves a password given a label from the Keychain
func passwordFromKeychain(label string) (string, error) {
	data, err := readBiometricItem(label)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func storePasswordInKeychain(label, keyInfo string, pin []byte, logger *log.Logger) error {
	err := storePasswordWithBiometric(label, "GnuPG", keyInfo, pin)
	if err == errKeychainDuplicate {
		logger.Printf("Existing entry blocks insertion, deleting and retrying")
		if delErr := deleteKeychainItem("GnuPG", keyInfo); delErr != nil {
			return fmt.Errorf("deleting existing entry: %w", delErr)
		}
		err = storePasswordWithBiometric(label, "GnuPG", keyInfo, pin)
	}
	return err
}

// passwordPrompt uses the default pinentry-mac program for getting the password from the user
func passwordPrompt(s pinentry.Settings) ([]byte, error) {
	p, err := pinentryBinary.New()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to start %q: %w", pinentryBinary.GetBinary(), err)
	}
	defer p.Close()

	p.Set("title", "pinentry-touchid PIN Prompt")

	// passthrough the original description that its used for creating the keychain item
	p.Set("desc", strings.ReplaceAll(s.Desc, "\n", "\\n"))

	// Enable opt-in external PIN caching (in the OS keychain).
	// https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65#file-info-pinentry-L324
	//
	// Ideally if this option was not set, pinentry-mac should hide the `Save in Keychain`
	// checkbox, but this is not the case.
	// p.Option("allow-external-password-cache")
	p.Set("KEYINFO", s.KeyInfo)
	if s.Prompt != "" {
		p.Set("PROMPT", s.Prompt)
	} else {
		// set "PIN" as the default prompt
		p.Set("PROMPT", "PIN")
	}
	if s.RepeatPrompt != "" {
		p.Set("REPEAT", s.RepeatPrompt)
	}
	p.Set("REPEATERROR", s.RepeatError)

	return p.GetPin()
}

func assuanError(err error) *common.Error {
	return &common.Error{
		Src:     common.ErrSrcPinentry,
		SrcName: "pinentry",
		Code:    common.ErrCanceled,
		Message: err.Error(),
	}
}

// GetPIN executes the main logic for returning a password/pin back to the gpg-agent
func (c KeychainClient) GetPIN(s pinentry.Settings) (string, *common.Error) {
	if len(s.Error) == 0 && len(s.RepeatPrompt) == 0 && s.Opts.AllowExtPasswdCache && len(s.KeyInfo) != 0 {
		return GetPIN(c.promptFn, c.logger)(s)
	}

	// fallback to pinentry-mac in any other case
	pin, err := c.promptFn(s)
	if err != nil {
		return "", assuanError(err)
	}

	// TODO(jorge): try to persist automatically in the keychain?
	return string(pin), nil
}

// Confirm Asks for confirmation, not implemented.
func (c KeychainClient) Confirm(s pinentry.Settings) (bool, *common.Error) {
	c.logger.Println("Confirm was called!")

	if _, err := c.promptFn(s); err != nil {
		return false, assuanError(err)
	}

	return true, nil
}

// Msg shows a message, not implemented.
func (c KeychainClient) Msg(pinentry.Settings) *common.Error {
	c.logger.Println("Msg was called!")

	return nil
}

// GetPIN executes the main logic for returning a password/pin back to the gpg-agent
func GetPIN(promptFn PromptFunc, logger *log.Logger) GetPinFunc {
	return func(s pinentry.Settings) (string, *common.Error) {
		logger.Printf("GETPIN called with desc: %s", s.Desc)
		matches := emailRegex.FindStringSubmatch(s.Desc)
		name := ""
		email := ""

		if len(matches) > 2 {
			// matches[1] is "Name (parenthetical comment) <email>"; the comment
			// must be stripped so the keychain label matches across sessions.
			fullName := strings.Split(matches[1], " <")[0]
			if idx := strings.Index(fullName, " ("); idx != -1 {
				name = fullName[:idx]
			} else {
				name = fullName
			}
			email = matches[2]
			logger.Printf("Parsed name: %s, email: %s", name, email)
		}

		keyID := ""

		matches = keyIDRegex.FindStringSubmatch(s.Desc)
		if len(matches) >= 2 {
			keyID = matches[1]
		} else {
			matches = sshKeyIDRegex.FindStringSubmatch(s.Desc)
			if len(matches) >= 1 {
				keyID = matches[1]
				name = "ssh"
				email = keyID
			}
		}

		// Drop the optional 0x prefix from keyID (--keyid-format)
		// https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html
		keyID = strings.TrimPrefix(keyID, "0x")

		if len(keyID) != expectedKeyLengthGPG && len(keyID) != expectedKeyLengthFullGPG && len(keyID) != expectedKeyLengthSSH {
			return "", assuanError(fmt.Errorf("invalid keyID: %s", keyID))
		}

		keychainLabel := fmt.Sprintf("%s <%s> (%s)", name, email, keyID)
		// s.KeyInfo is "<x>/<cacheId>" — see
		// https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65#file-info-pinentry-L357-L362
		keyInfo := strings.Split(s.KeyInfo, "/")[1]

		// Single keychain op: the read triggers one Touch ID. A missing entry
		// returns errEmptyResults *without* prompting, so there's no separate
		// existence check to cause a second prompt.
		fetchStart := time.Now()
		password, err := passwordFromKeychain(keychainLabel)
		switch {
		case err == nil:
			logger.Printf("Password fetched from keychain after %s", time.Since(fetchStart))
			return password, nil
		case err != errEmptyResults:
			logger.Printf("Error fetching password from keychain after %s: %s", time.Since(fetchStart), err)
			return "", assuanError(err)
		}

		// No entry yet — prompt via pinentry-mac and store it for next time.
		logger.Printf("No keychain entry for %q; prompting", keychainLabel)
		pin, err := promptFn(s)
		if err != nil {
			logger.Printf("Error calling pinentry program (%s): %s", pinentryBinary.GetBinary(), err)
		}
		if len(pin) == 0 {
			logger.Printf("pinentry-mac didn't return a password")
			return "", assuanError(fmt.Errorf("pinentry-mac didn't return a password"))
		}
		if err := storePasswordInKeychain(keychainLabel, keyInfo, pin, logger); err != nil {
			logger.Printf("Error storing password in keychain: %s", err)
			return "", assuanError(err)
		}
		return string(pin), nil
	}
}

// validatePINBinary validates that the pinentry program returned by gpgconf
// is/points to pinentry-mac
func validatePINBinary() (string, error) {
	binaryPath := pinentryBinary.GetBinary()
	originalPath := binaryPath
	if _, err := exec.LookPath(binaryPath); err != nil {
		return binaryPath, errors.New("PIN entry program not found")
	}

	// check if the binary is (or resolves to -- if it is a symlink) to pinentry-mac
	info, err := os.Lstat(binaryPath)
	if err != nil {
		return binaryPath, fmt.Errorf("Couldn't lstat file: %w", err)
	}

	if info.Mode()&fs.ModeSymlink != 0 {
		// the file is a symlink so we check that the resolved path contains
		// pinentry-mac
		path, err := filepath.EvalSymlinks(binaryPath)
		if err != nil {
			return binaryPath, fmt.Errorf("Couldn't resolve symlink: %w", err)
		}

		binaryPath = path
	}
	if !strings.Contains(binaryPath, "pinentry-mac") {
		return "", errors.New(
			fmt.Sprintf("%s is a symlink that resolves to %s not to pinentry-mac",
				originalPath, binaryPath))
	}

	return binaryPath, nil
}

// fixPINBinary forces pinentry-mac as the fallback pinentry program
func fixPINBinary(oldPath string) error {
	newPath, err := exec.LookPath("pinentry-mac")
	if err != nil {
		return errors.New("pinentry-mac couldn't be found in your PATH")
	}

	if err := os.Remove(oldPath); err != nil {
		return fmt.Errorf("Unable to remove symlink: %w", err)
	}

	// create the new symlink pointing to pinentry-mac
	if err := os.Symlink(newPath, oldPath); err != nil {
		return fmt.Errorf("Unable to symlink to pinentry-mac: %w", err)
	}

	return nil
}

// getInfoHandler handles GETINFO commands
func getInfoHandler(pipe io.ReadWriter, _ interface{}, params string) *common.Error {
	if params == "" {
		return &common.Error{
			Src:     common.ErrSrcAssuan,
			Code:    common.ErrAssInvValue,
			SrcName: "assuan",
			Message: "missing argument",
		}
	}

	var data string
	switch params {
	case "flavor":
		data = "touchid"
	case "version":
		data = version
	case "pid":
		data = strconv.Itoa(os.Getpid())
	case "ttyinfo":
		// ttyinfo := "<tty> <ownerpid> <term>"
		ttyinfo := fmt.Sprintf("%s %d %s",
			os.Getenv("GPG_TTY"),
			os.Getppid(),
			os.Getenv("TERM"))
		data = strings.TrimSpace(ttyinfo)
	default:
		return &common.Error{
			Src:     common.ErrSrcAssuan,
			Code:    common.ErrNotFound,
			SrcName: "assuan",
			Message: "unknown value",
		}
	}

	common.WriteData(pipe, []byte(data))
	return nil
}

// serveWithCustomHandlers extends pinentry.Serve with custom command handlers
func serveWithCustomHandlers(callbacks pinentry.Callbacks, greeting string) error {
	info := pinentry.ProtoInfo
	info.Greeting = greeting

	// Add the GETINFO handler
	info.Handlers["GETINFO"] = getInfoHandler

	// Add the standard pinentry handlers
	info.Handlers["GETPIN"] = func(pipe io.ReadWriter, state interface{}, _ string) *common.Error {
		if callbacks.GetPIN == nil {
			return &common.Error{
				Src:     common.ErrSrcPinentry,
				Code:    common.ErrNotImplemented,
				SrcName: "pinentry",
				Message: "GETPIN op is not supported",
			}
		}
		pass, err := callbacks.GetPIN(*state.(*pinentry.Settings))
		if err != nil {
			return err
		}
		common.WriteData(pipe, []byte(pass))
		return nil
	}

	info.Handlers["CONFIRM"] = func(pipe io.ReadWriter, state interface{}, _ string) *common.Error {
		if callbacks.Confirm == nil {
			return &common.Error{
				Src:     common.ErrSrcPinentry,
				Code:    common.ErrNotImplemented,
				SrcName: "pinentry",
				Message: "CONFIRM op is not supported",
			}
		}
		v, err := callbacks.Confirm(*state.(*pinentry.Settings))
		if err != nil {
			return err
		}
		if !v {
			return &common.Error{
				Src:     common.ErrSrcPinentry,
				Code:    common.ErrCanceled,
				SrcName: "pinentry",
				Message: "operation canceled",
			}
		}
		return nil
	}

	info.Handlers["MESSAGE"] = func(pipe io.ReadWriter, state interface{}, _ string) *common.Error {
		if callbacks.Msg == nil {
			return &common.Error{
				Src:     common.ErrSrcPinentry,
				Code:    common.ErrNotImplemented,
				SrcName: "pinentry",
				Message: "MESSAGE op is not supported",
			}
		}
		return callbacks.Msg(*state.(*pinentry.Settings))
	}

	return server.ServeStdin(info)
}

func main() {
	flag.Parse()
	if !sensor.IsTouchIDAvailable() {
		client, err := pinentry.LaunchCustom("pinentry-mac")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Pinentry Launch returned error: %v\n", err)
			os.Exit(-1)
		}
		callbacks := pinentry.Callbacks{
			GetPIN:  client.GetPIN,
			Confirm: client.Confirm,
			Msg:     client.Message,
		}

		if err := pinentry.Serve(callbacks, "Hi from pinentry-mac!"); err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "Pinentry Serve returned error: %v\n", err)
			os.Exit(-1)
		}
		return
	}

	if *selfTest {
		ok := true

		// Check Touch ID
		if sensor.IsTouchIDAvailable() {
			fmt.Fprintf(os.Stdout, "Touch ID:    available\n")
		} else {
			fmt.Fprintf(os.Stdout, "Touch ID:    unavailable\n")
			ok = false
		}

		// Check log file writability
		logPath := filepath.Clean(DefaultLogLocation)
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stdout, "Log file:    %s (not writable: %v)\n", logPath, err)
			ok = false
		} else {
			f.Close()
			fmt.Fprintf(os.Stdout, "Log file:    %s (writable)\n", logPath)
		}

		// Check fallback pinentry binary
		fallbackPath, err := validatePINBinary()
		if err != nil {
			fmt.Fprintf(os.Stdout, "Fallback:    %s (%v)\n", fallbackPath, err)
			ok = false
		} else {
			fmt.Fprintf(os.Stdout, "Fallback:    %s\n", fallbackPath)
		}

		// Version
		fmt.Fprintf(os.Stdout, "Version:     %s\n", version)

		if !ok {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *fixSymlink {
		path := pinentryBinary.GetBinary()
		if err := fixPINBinary(path); err != nil {
			fmt.Fprintf(os.Stderr, "%v %s\n", emoji.CrossMark, err)
			os.Exit(-1)
		}

		fmt.Fprintf(os.Stderr, "%v %s is now pointing to pinentry-mac\n", emoji.CheckMarkButton, path)
		os.Exit(0)
	}

	if *check {
		path, err := validatePINBinary()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v %s %s\n", emoji.CrossMark, err, path)
			os.Exit(-1)
		}

		if path != "" {
			fmt.Fprintf(os.Stdout, "%v %s will be used as a fallback PIN program\n", emoji.CheckMarkButton, path)
		}

		os.Exit(0)
	}

	client := New()

	callbacks := pinentry.Callbacks{
		GetPIN:  client.GetPIN,
		Confirm: client.Confirm,
		Msg:     client.Msg,
	}

	if err := serveWithCustomHandlers(callbacks, "Hi from pinentry-touchid!"); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Pinentry Serve returned error: %v\n", err)
		os.Exit(-1)
	}
}
