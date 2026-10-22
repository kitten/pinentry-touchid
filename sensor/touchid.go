// Copyright (c) 2021 Jorge Luis Betancourt. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.
//
//go:build darwin && cgo
// +build darwin,cgo

package sensor

/*
#cgo CFLAGS: -x objective-c -fmodules -fblocks
#cgo LDFLAGS: -framework CoreFoundation -framework LocalAuthentication -framework Foundation -framework Security -framework CoreGraphics -framework IOKit
#include <stdlib.h>
#include <stdio.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <Security/AuthSession.h>
#include <CoreGraphics/CoreGraphics.h>
#include <IOKit/IOKitLib.h>
#include <unistd.h>

// Missing or unrecognized state leaves the relevant bit unset (terminal preferred).
unsigned int consoleState() {
    unsigned int state = 0;
    SecuritySessionId securitySession;
    SessionAttributeBits attributes;
    if (SessionGetInfo(callerSecuritySession, &securitySession, &attributes) == errSecSuccess
        && (attributes & sessionHasGraphicAccess)) state |= 1;

    CFDictionaryRef session = CGSessionCopyCurrentDictionary();
    if (session) {
        CFNumberRef uid = CFDictionaryGetValue(session, kCGSessionUserIDKey);
        int userID = -1;
        if (uid && CFGetTypeID(uid) == CFNumberGetTypeID()
            && CFNumberGetValue(uid, kCFNumberIntType, &userID)
            && userID == geteuid()
            && CFDictionaryGetValue(session, kCGSessionOnConsoleKey) == kCFBooleanTrue
            && CFDictionaryGetValue(session, kCGSessionLoginDoneKey) == kCFBooleanTrue) state |= 2;
        CFRelease(session);
    }

    // IOConsoleLocked is an undocumented registry property, defined in Apple's
    // xnu IOKitKeysPrivate.h. Require an explicit false rather than guessing.
    io_registry_entry_t root = IORegistryGetRootEntry(kIOMainPortDefault);
    if (root) {
        CFTypeRef locked = IORegistryEntryCreateCFProperty(root, CFSTR("IOConsoleLocked"), kCFAllocatorDefault, 0);
        if (locked == kCFBooleanFalse) state |= 4;
        if (locked) CFRelease(locked);
        IOObjectRelease(root);
    }

    uint32_t count = 0;
    if (CGGetOnlineDisplayList(0, NULL, &count) == kCGErrorSuccess && count > 0) {
        CGDirectDisplayID *displays = calloc(count, sizeof(CGDirectDisplayID));
        if (displays) {
            if (CGGetOnlineDisplayList(count, displays, &count) == kCGErrorSuccess) {
                for (uint32_t i = 0; i < count; i++) {
                    if (CGDisplayIsActive(displays[i]) && !CGDisplayIsAsleep(displays[i])) {
                        state |= 8;
                        break;
                    }
                }
            }
            free(displays);
        }
    }
    return state;
}

int isTouchIDAvailable() {
    int result = 0;
    bool success = [[[LAContext alloc] init] canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
    if (success) {
        return 1;
    }

    return 0;
}
*/
import (
	"C"
)

// IsTouchIDAvailable checks if Touch ID is available in the current device
func IsTouchIDAvailable() bool {
	result := C.isTouchIDAvailable()

	return result == 1
}

// CurrentConsoleState samples the console without waking displays or prompting.
func CurrentConsoleState() ConsoleState {
	state := uint32(C.consoleState())
	return ConsoleState{GUIAccess: state&1 != 0, OnConsole: state&2 != 0, Unlocked: state&4 != 0, DisplayAwake: state&8 != 0}
}
