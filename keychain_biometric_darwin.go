//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

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
        kSecUseDataProtectionKeychain,
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
        kCFBooleanTrue,
    };

    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 9,
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

    const void* keys[]   = { kSecClass, kSecAttrService, kSecAttrAccount, kSecUseDataProtectionKeychain };
    const void* values[] = { kSecClassGenericPassword, service, account, kCFBooleanTrue };

    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 4,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    OSStatus status = SecItemDelete(query);

    CFRelease(query);
    CFRelease(service); CFRelease(account);
    return status;
}

// Reports whether a data-protection generic-password with this label exists and
// carries the biometric marker. Reads attributes only, so it never prompts.
static OSStatus pt_checkBiometricItem(
    const UInt8* labelBytes, CFIndex labelLen,
    const UInt8* markerBytes, CFIndex markerLen,
    int* outMatched
) {
    *outMatched = 0;
    CFStringRef label  = CFStringCreateWithBytes(NULL, labelBytes,  labelLen,  kCFStringEncodingUTF8, false);
    CFStringRef marker = CFStringCreateWithBytes(NULL, markerBytes, markerLen, kCFStringEncodingUTF8, false);

    const void* keys[]   = { kSecClass, kSecAttrLabel, kSecMatchLimit, kSecReturnAttributes, kSecUseDataProtectionKeychain };
    const void* values[] = { kSecClassGenericPassword, label, kSecMatchLimitOne, kCFBooleanTrue, kCFBooleanTrue };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 5,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (status == errSecSuccess && result != NULL) {
        CFStringRef desc = (CFStringRef)CFDictionaryGetValue((CFDictionaryRef)result, kSecAttrDescription);
        if (desc != NULL && CFStringCompare(desc, marker, 0) == kCFCompareEqualTo) {
            *outMatched = 1;
        }
    }
    if (result != NULL) CFRelease(result);
    CFRelease(query); CFRelease(label); CFRelease(marker);
    if (status == errSecItemNotFound) return errSecSuccess;
    return status;
}

// Returns the secret for the labelled data-protection item, triggering Touch ID
// at SecItemCopyMatching time. Caller must free(*outData).
static OSStatus pt_readBiometricItem(
    const UInt8* labelBytes, CFIndex labelLen,
    UInt8** outData, CFIndex* outLen
) {
    *outData = NULL; *outLen = 0;
    CFStringRef label = CFStringCreateWithBytes(NULL, labelBytes, labelLen, kCFStringEncodingUTF8, false);

    const void* keys[]   = { kSecClass, kSecAttrLabel, kSecMatchLimit, kSecReturnData, kSecUseDataProtectionKeychain };
    const void* values[] = { kSecClassGenericPassword, label, kSecMatchLimitOne, kCFBooleanTrue, kCFBooleanTrue };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 5,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (status == errSecSuccess && result != NULL) {
        CFDataRef data = (CFDataRef)result;
        CFIndex len = CFDataGetLength(data);
        UInt8* buf = (UInt8*)malloc(len);
        if (buf != NULL) {
            memcpy(buf, CFDataGetBytePtr(data), len);
            *outData = buf;
            *outLen = len;
        }
    }
    if (result != NULL) CFRelease(result);
    CFRelease(query); CFRelease(label);
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
// tell them apart from legacy entries.
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

// checkBiometricItem reports whether a biometric-marked item with this label
// exists in the data-protection keychain. Reads attributes only — no Touch ID.
func checkBiometricItem(label string) (bool, error) {
	labelPtr, labelLen := bytesPtr([]byte(label))
	markerPtr, markerLen := bytesPtr([]byte(biometricDescriptionMarker))

	var matched C.int
	status := C.pt_checkBiometricItem(labelPtr, labelLen, markerPtr, markerLen, &matched)
	if status != 0 {
		return false, fmt.Errorf("SecItemCopyMatching (check) failed with OSStatus %d", status)
	}
	return matched == 1, nil
}

// readBiometricItem returns the secret for a labelled data-protection item,
// prompting Touch ID. Returns errEmptyResults when no entry exists.
func readBiometricItem(label string) ([]byte, error) {
	labelPtr, labelLen := bytesPtr([]byte(label))

	var data *C.UInt8
	var length C.CFIndex
	status := C.pt_readBiometricItem(labelPtr, labelLen, &data, &length)
	if status == errSecItemNotFound {
		return nil, errEmptyResults
	}
	if status != 0 {
		return nil, fmt.Errorf("SecItemCopyMatching (read) failed with OSStatus %d", status)
	}
	if data == nil {
		return nil, errEmptyResults
	}
	defer C.free(unsafe.Pointer(data))
	return C.GoBytes(unsafe.Pointer(data), C.int(length)), nil
}

// Handles the zero-length case where &b[0] would panic.
func bytesPtr(b []byte) (*C.UInt8, C.CFIndex) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.UInt8)(unsafe.Pointer(&b[0])), C.CFIndex(len(b))
}
