//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

// Reads of biometric-ACL items trigger Touch ID at SecItemCopyMatching time —
// no per-app ACL whitelist, so the item survives binary rebuilds (new CDHash).
static OSStatus pt_addBiometricItem(
    const UInt8* labelBytes, CFIndex labelLen,
    const UInt8* serviceBytes, CFIndex serviceLen,
    const UInt8* accountBytes, CFIndex accountLen,
    const UInt8* dataBytes, CFIndex dataLen,
    const UInt8* commentBytes, CFIndex commentLen
) {
    CFStringRef label       = CFStringCreateWithBytes(NULL, labelBytes,   labelLen,   kCFStringEncodingUTF8, false);
    CFStringRef service     = CFStringCreateWithBytes(NULL, serviceBytes, serviceLen, kCFStringEncodingUTF8, false);
    CFStringRef account     = CFStringCreateWithBytes(NULL, accountBytes, accountLen, kCFStringEncodingUTF8, false);
    CFStringRef description = CFStringCreateWithBytes(NULL, commentBytes, commentLen, kCFStringEncodingUTF8, false);
    CFDataRef   data        = CFDataCreate(NULL, dataBytes, dataLen);

    CFErrorRef cfErr = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryAny,
        &cfErr
    );

    if (access == NULL) {
        if (cfErr != NULL) CFRelease(cfErr);
        CFRelease(label); CFRelease(service); CFRelease(account); CFRelease(description); CFRelease(data);
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
        kSecAttrDescription,
    };
    const void* values[] = {
        kSecClassGenericPassword,
        label,
        service,
        account,
        data,
        access,
        kCFBooleanFalse,
        description,
    };

    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 8,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemAdd(query, NULL);

    CFRelease(query);
    CFRelease(access);
    CFRelease(label); CFRelease(service); CFRelease(account); CFRelease(description); CFRelease(data);
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

const (
	errSecDuplicateItem      = -25299
	errSecItemNotFound       = -25300
	errSecMissingEntitlement = -34018
)

// Stored in kSecAttrDescription on biometric items so the read path can
// tell them apart from legacy entries. kSecAttrComment would be the more
// idiomatic choice but keybase/go-keychain's QueryResult doesn't expose it.
const biometricDescriptionMarker = "pinentry-touchid-biometric-v1"

var (
	errKeychainDuplicate  = errors.New("keychain entry already exists")
	errMissingEntitlement = errors.New("missing keychain-access-groups entitlement")
)

func storePasswordWithBiometric(label, service, account string, password []byte) error {
	labelPtr, labelLen := bytesPtr([]byte(label))
	servicePtr, serviceLen := bytesPtr([]byte(service))
	accountPtr, accountLen := bytesPtr([]byte(account))
	dataPtr, dataLen := bytesPtr(password)
	commentPtr, commentLen := bytesPtr([]byte(biometricDescriptionMarker))

	status := C.pt_addBiometricItem(
		labelPtr, labelLen,
		servicePtr, serviceLen,
		accountPtr, accountLen,
		dataPtr, dataLen,
		commentPtr, commentLen,
	)

	switch status {
	case 0:
		return nil
	case errSecDuplicateItem:
		return errKeychainDuplicate
	case errSecMissingEntitlement:
		return errMissingEntitlement
	default:
		return fmt.Errorf("SecItemAdd failed with OSStatus %d", status)
	}
}

// Returns nil if the entry didn't exist.
func deleteKeychainItem(service, account string) error {
	servicePtr, serviceLen := bytesPtr([]byte(service))
	accountPtr, accountLen := bytesPtr([]byte(account))

	status := C.pt_deleteItem(servicePtr, serviceLen, accountPtr, accountLen)
	if status != 0 && status != errSecItemNotFound {
		return fmt.Errorf("SecItemDelete failed with OSStatus %d", status)
	}
	return nil
}

// Handles the zero-length case where &b[0] would panic.
func bytesPtr(b []byte) (*C.UInt8, C.CFIndex) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.UInt8)(unsafe.Pointer(&b[0])), C.CFIndex(len(b))
}
