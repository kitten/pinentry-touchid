//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
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
        // CurrentSet, not Any: enrolling a new fingerprint invalidates the item.
        kSecAccessControlBiometryCurrentSet,
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

// Returns the secret for the (service, account) data-protection item, triggering
// Touch ID at SecItemCopyMatching time. Keyed on service+account (not label) so a
// dual sign+auth key — same account, different labels — resolves to one item.
// prompt is shown in the Touch ID dialog. *outLegacy is set when the item's marker
// differs from the current one, so the caller can re-store it under today's ACL.
// Caller must free(*outData).
static OSStatus pt_readBiometricItem(
    const UInt8* serviceBytes, CFIndex serviceLen,
    const UInt8* accountBytes, CFIndex accountLen,
    const UInt8* promptBytes, CFIndex promptLen,
    const UInt8* markerBytes, CFIndex markerLen,
    UInt8** outData, CFIndex* outLen, int* outLegacy
) {
    *outData = NULL; *outLen = 0; *outLegacy = 0;
    CFStringRef service = CFStringCreateWithBytes(NULL, serviceBytes, serviceLen, kCFStringEncodingUTF8, false);
    CFStringRef account = CFStringCreateWithBytes(NULL, accountBytes, accountLen, kCFStringEncodingUTF8, false);
    CFStringRef prompt  = CFStringCreateWithBytes(NULL, promptBytes,  promptLen,  kCFStringEncodingUTF8, false);
    CFStringRef marker  = CFStringCreateWithBytes(NULL, markerBytes,  markerLen,  kCFStringEncodingUTF8, false);

    const void* keys[]   = { kSecClass, kSecAttrService, kSecAttrAccount, kSecMatchLimit, kSecReturnData, kSecReturnAttributes, kSecUseDataProtectionKeychain, kSecUseOperationPrompt };
    const void* values[] = { kSecClassGenericPassword, service, account, kSecMatchLimitOne, kCFBooleanTrue, kCFBooleanTrue, kCFBooleanTrue, prompt };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 8,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (status == errSecSuccess && result != NULL) {
        CFDictionaryRef dict = (CFDictionaryRef)result;
        CFDataRef data = (CFDataRef)CFDictionaryGetValue(dict, kSecValueData);
        if (data != NULL) {
            CFIndex len = CFDataGetLength(data);
            UInt8* buf = (UInt8*)malloc(len);
            if (buf != NULL) {
                memcpy(buf, CFDataGetBytePtr(data), len);
                *outData = buf;
                *outLen = len;
            }
        }
        CFStringRef desc = (CFStringRef)CFDictionaryGetValue(dict, kSecAttrDescription);
        if (desc == NULL || !CFEqual(desc, marker)) {
            *outLegacy = 1;
        }
    }
    if (result != NULL) CFRelease(result);
    CFRelease(query); CFRelease(service); CFRelease(account); CFRelease(prompt); CFRelease(marker);
    return status;
}

// proc_name (libproc) maps a PID to its command name via syscall, no subprocess.
static int pt_processName(int pid, char* buf, int bufLen) {
    return proc_name(pid, buf, (uint32_t)bufLen);
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
const biometricDescriptionMarker = "pinentry-touchid-biometric-v2"

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

// readBiometricItem returns the secret for the (service, account) item,
// prompting Touch ID with reason. legacy is true when the stored item predates
// the current ACL marker. Returns errEmptyResults when no entry exists.
func readBiometricItem(service, account, reason string) ([]byte, bool, error) {
	servicePtr, serviceLen := bytesPtr([]byte(service))
	accountPtr, accountLen := bytesPtr([]byte(account))
	promptPtr, promptLen := bytesPtr([]byte(reason))
	markerPtr, markerLen := bytesPtr([]byte(biometricDescriptionMarker))

	var data *C.UInt8
	var length C.CFIndex
	var legacy C.int
	status := C.pt_readBiometricItem(servicePtr, serviceLen, accountPtr, accountLen,
		promptPtr, promptLen, markerPtr, markerLen, &data, &length, &legacy)
	if status == errSecItemNotFound {
		return nil, false, errEmptyResults
	}
	if status != 0 {
		return nil, false, fmt.Errorf("SecItemCopyMatching (read) failed with OSStatus %d", status)
	}
	if data == nil {
		return nil, false, errEmptyResults
	}
	defer C.free(unsafe.Pointer(data))
	return C.GoBytes(unsafe.Pointer(data), C.int(length)), legacy != 0, nil
}

// processName returns the command name for pid, or "" if it can't be resolved.
func processName(pid int) string {
	buf := make([]byte, 64)
	n := C.pt_processName(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

// Handles the zero-length case where &b[0] would panic.
func bytesPtr(b []byte) (*C.UInt8, C.CFIndex) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.UInt8)(unsafe.Pointer(&b[0])), C.CFIndex(len(b))
}
