# pinentry-touchid

> **🚀 This fork includes critical fixes for GnuPG 2.4+ compatibility**
>
> These fixes resolve errors including "error: gpg failed to sign the data", "failed to unprotect the secret key: Operation cancelled", and "You may want to update to a newer pinentry".
>
> Key changes:
> - ✅ **GETINFO support** - Implements `GETINFO flavor/version/pid/ttyinfo` commands required by GnuPG 2.4+
> - ✅ **Biometric keychain ACL** - Keychain items are stored with `kSecAccessControlBiometryAny`, so Touch ID is enforced by the keychain itself and survives binary rebuilds without re-prompting "Always Allow"
> - ✅ **Codesigned binary** - The Homebrew and default Nix packages use a Developer ID-signed app with a `keychain-access-groups` entitlement (required for biometric ACL on `SecItemAdd`)
> - ✅ **Name parsing fix** - Correctly strips GPG key comments to match existing keychain entries
> - ✅ **Duplicate entry handling** - Gracefully handles duplicate keychain entries instead of failing
>

<p align="center">
    <img class="center" src="https://user-images.githubusercontent.com/1291846/127916161-5803ca98-c0a2-4d1f-8479-860f4d7edc98.png" width="300" alt="pinentry-touchid logo"/>
</p>

Custom GPG pinentry program for macOS that allows using Touch ID for fetching the password from the
macOS keychain.

> **Compatible with GnuPG 2.4+** - This version includes support for the GETINFO commands required by modern GnuPG versions.

> Touch ID requires a Mac with a Touch ID sensor. When Touch ID is unavailable,
> graphical sessions use `pinentry-mac`; terminal sessions use `pinentry-curses`.

## See it in action

 ![pinentry-touchid in action with gopass](https://user-images.githubusercontent.com/1291846/128176593-271ac649-5207-41f2-83da-3fb3d37ede9c.gif)


## How does it work

`pinentry-touchid` stores the PIN in a Keychain item whose access control is
`kSecAccessControlBiometryAny`. macOS enforces Touch ID at the keychain layer:
any read of the item prompts for Touch ID via the system modal, regardless of
which binary is doing the reading. Rebuilding the binary (new CDHash) no longer
invalidates a prior "Always Allow" because there's no per-app ACL whitelist in
the first place.

Flow:

- **No entry yet** — falls back to `pinentry-mac` to prompt for the PIN, then
  stores it with biometric ACL. Uncheck <kbd>Save in keychain</kbd> in
  pinentry-mac's dialog so it doesn't create a parallel entry.

- **Legacy (pre-biometric) entry exists** — treated as if no entry exists: you
  re-enter the PIN once via `pinentry-mac` and we replace the legacy item with
  a biometric one. After that, Touch ID prompts only.

- **Biometric entry exists** — read triggers the Touch ID modal; on success the
  PIN is returned to `gpg-agent`.

### Terminal fallback

Graphical authentication is preferred only when the current user's console
session is active, unlocked, and has an awake display, and the process has
graphical access. Otherwise pinentry-touchid runs `pinentry-curses` directly,
bypassing Touch ID and Keychain access. Nonempty `SSH_CONNECTION`, `SSH_CLIENT`,
or `SSH_TTY` selects terminal input even when Screen Sharing keeps the console
unlocked. The `-tty` flag always forces terminal input. `-self-test` prints the
selection reason without logging environment values.

These SSH markers must reach the pinentry process. A shared `gpg-agent` does not
reliably receive the requesting shell's SSH environment. For GPG requests,
`PINENTRY_USER_DATA=pinentry-touchid:tty` explicitly selects terminal input via
GnuPG's supported per-request environment forwarding. SSH-agent requests do not
carry the caller's terminal or environment; their routing still depends on the
agent's startup environment. Updating that environment affects other sessions,
so a shared agent cannot reliably distinguish simultaneous local and remote SSH
clients. Do not treat an unlocked console as proof that a request is local.

Detection samples macOS state at startup, without waking the screen. It uses
Core Graphics session/display APIs and the undocumented `IOConsoleLocked`
IORegistry property (defined in Apple's XNU sources). Missing or unrecognized
state selects terminal input. `-self-test` reports each signal and selected mode.
A console can lock after the check; Touch ID cancellation does not trigger a
second password prompt. The Apple headless virtual display (vendor `unkn`, model `virt`) is excluded
from awake-display detection. Other virtual-display drivers may still count as
available; this is not a universal physical-display detector.

Install `pinentry-curses` on PATH; the Homebrew and Nix packages include it.
GnuPG must supply a usable terminal (`export GPG_TTY=$(tty)` in interactive shells). Without a
terminal, curses cannot provide an interactive prompt.

The default Nix package downloads a signed release. Source changes become active
there only after building/signing a new release and updating its version and hash.

### Codesigning

The Homebrew and default Nix packages use the Developer ID-signed release app,
including its provisioning profile and `keychain-access-groups` entitlement.
Keep the app bundle intact; a plain `go build` does not produce a signed app
that can create biometric Keychain items.

### Security

The biometric ACL means Touch ID is the actual gate — it can't be bypassed by
code in pinentry-touchid (or any other process).

## Installation

### Homebrew

The [kitten/tap](https://github.com/kitten/homebrew-tap) package supports macOS 14+
on Apple silicon. Install it with:

```sh
$ brew install kitten/tap/pinentry-touchid
```

It includes `pinentry-mac` for graphical prompts and `pinentry-curses` (from
Homebrew's `pinentry` formula) for terminal prompts. GnuPG must also be installed:

```sh
$ brew install gnupg
```

Installation does not change your GnuPG configuration. For the standard Apple
silicon Homebrew installation, manually add or replace the `pinentry-program`
line in `~/.gnupg/gpg-agent.conf` with:

```conf
pinentry-program /opt/homebrew/bin/pinentry-touchid
```

Then reload the agent:

```sh
$ gpg-connect-agent reloadagent /bye
```

When prompted by `pinentry-mac`, leave <kbd>Save in keychain</kbd> unchecked;
`pinentry-touchid` creates its own biometric entry. Existing legacy entries
are replaced after you enter the passphrase once.

### Manual installation

Download the signed app ZIP from the
[Releases page](https://github.com/kitten/pinentry-touchid/releases). The current
release supports macOS 14+ on Apple silicon; it does not include an Intel Mac
or Linux binary. Extract it and keep `pinentry-touchid.app` intact.

Install GnuPG, `pinentry-mac`, and `pinentry-curses`, and ensure both fallback
pinentries are on the PATH available to `gpg-agent`. Set `pinentry-program` in
`~/.gnupg/gpg-agent.conf` to the absolute path of
`pinentry-touchid.app/Contents/MacOS/pinentry-touchid`, then reload the agent as
shown above. See [Terminal fallback](#terminal-fallback) for terminal requirements.

For an existing setup, `pinentry-touchid -check` checks that the graphical
fallback reported by `gpgconf` points to `pinentry-mac`. If it reports an
incorrect symlink, `pinentry-touchid -fix` can replace that symlink; this is a
separate repair step, not part of selecting pinentry-touchid in GnuPG. A shell
alias does not configure the agent's fallback.

## Disclaimer

This project does not store the password/pin in the [Secure
Enclave](https://support.apple.com/en-gb/guide/security/sec59b0b31ff/web) of your device, instead
uses a Keychain item protected by biometric access control.

## Tested on

Earlier versions were tested on the following devices and macOS versions;
these are historical results, not the current release platform requirements:

* MacBook Pro (15-inch, 2018), macOS Catalina - 10.15.7
* MacBook Pro (15-inch, 2018), macOS Big Sur - 11.4, 11.5.0, 11.5.1
* MacBook Pro (16-inch, Late 2019), macOS Big Sur - 11.4, 11.5.1
* MacBook Pro (16-inch, Late 2021), macOS Monterey - 12.2

## Links

* The project icon is taken from <a href="https://icons8.com/icon/BebbEec6QUjh/touch-id">Touch ID icon by Icons8</a>.
