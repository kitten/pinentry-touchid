//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

// Adds a generic-password item protected by a biometric SecAccessControl.
// Every subsequent read of the item triggers macOS's standard Touch ID
// modal — no per-app ACL whitelist is involved, so rebuilding the binary
// (which produces a new nix store path) does not invalidate access.
static OSStatus pt_addBiometricItem(
    const UInt8* labelBytes, CFIndex labelLen,
    const UInt8* serviceBytes, CFIndex serviceLen,
    const UInt8* accountBytes, CFIndex accountLen,
    const UInt8* dataBytes, CFIndex dataLen
) {
    CFStringRef label   = CFStringCreateWithBytes(NULL, labelBytes,   labelLen,   kCFStringEncodingUTF8, false);
    CFStringRef service = CFStringCreateWithBytes(NULL, serviceBytes, serviceLen, kCFStringEncodingUTF8, false);
    CFStringRef account = CFStringCreateWithBytes(NULL, accountBytes, accountLen, kCFStringEncodingUTF8, false);
    CFDataRef   data    = CFDataCreate(NULL, dataBytes, dataLen);

    CFErrorRef cfErr = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryAny,
        &cfErr
    );

    if (access == NULL) {
        if (cfErr != NULL) CFRelease(cfErr);
        CFRelease(label); CFRelease(service); CFRelease(account); CFRelease(data);
        return errSecAuthFailed;
    }

    const void* keys[] = {
        kSecClass,
        kSecAttrLabel,
        kSecAttrService,
        kSecAttrAccount,
        kSecValueData,
        kSecAttrAccessControl,
        kSecAttrSynchronizable,
    };
    const void* values[] = {
        kSecClassGenericPassword,
        label,
        service,
        account,
        data,
        access,
        kCFBooleanFalse,
    };

    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 7,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemAdd(query, NULL);

    CFRelease(query);
    CFRelease(access);
    CFRelease(label); CFRelease(service); CFRelease(account); CFRelease(data);
    return status;
}

// Deletes a generic-password entry by (service, account). Used to migrate
// existing non-biometric entries to biometric ACL.
static OSStatus pt_deleteItem(
    const UInt8* serviceBytes, CFIndex serviceLen,
    const UInt8* accountBytes, CFIndex accountLen
) {
    CFStringRef service = CFStringCreateWithBytes(NULL, serviceBytes, serviceLen, kCFStringEncodingUTF8, false);
    CFStringRef account = CFStringCreateWithBytes(NULL, accountBytes, accountLen, kCFStringEncodingUTF8, false);

    const void* keys[]   = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void* values[] = { kSecClassGenericPassword, service, account };

    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemDelete(query);

    CFRelease(query);
    CFRelease(service); CFRelease(account);
    return status;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// macOS Security framework status codes (subset).
const (
	errSecDuplicateItem = -25299
	errSecItemNotFound  = -25300
)

// errKeychainDuplicate is returned by storePasswordWithBiometric when an
// item with the same (service, account) already exists. Callers should
// delete the existing entry and retry to migrate to biometric ACL.
var errKeychainDuplicate = errors.New("keychain entry already exists")

// storePasswordWithBiometric creates a keychain entry whose ACL requires
// biometric authentication on every read. No per-app whitelist is used,
// so the entry remains accessible across rebuilds of this binary.
func storePasswordWithBiometric(label, service, account string, password []byte) error {
	labelPtr, labelLen := bytesPtr([]byte(label))
	servicePtr, serviceLen := bytesPtr([]byte(service))
	accountPtr, accountLen := bytesPtr([]byte(account))
	dataPtr, dataLen := bytesPtr(password)

	status := C.pt_addBiometricItem(
		labelPtr, labelLen,
		servicePtr, serviceLen,
		accountPtr, accountLen,
		dataPtr, dataLen,
	)

	switch status {
	case 0:
		return nil
	case errSecDuplicateItem:
		return errKeychainDuplicate
	default:
		return fmt.Errorf("SecItemAdd failed with OSStatus %d", status)
	}
}

// deleteKeychainItem removes a (service, account) entry. Returns nil if
// the entry didn't exist.
func deleteKeychainItem(service, account string) error {
	servicePtr, serviceLen := bytesPtr([]byte(service))
	accountPtr, accountLen := bytesPtr([]byte(account))

	status := C.pt_deleteItem(servicePtr, serviceLen, accountPtr, accountLen)
	if status != 0 && status != errSecItemNotFound {
		return fmt.Errorf("SecItemDelete failed with OSStatus %d", status)
	}
	return nil
}

// bytesPtr returns a C pointer suitable for passing into CGO, handling the
// zero-length case where &b[0] would panic.
func bytesPtr(b []byte) (*C.UInt8, C.CFIndex) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.UInt8)(unsafe.Pointer(&b[0])), C.CFIndex(len(b))
}
