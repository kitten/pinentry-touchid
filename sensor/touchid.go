// Copyright (c) 2021 Jorge Luis Betancourt. All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0
// that can be found in the LICENSE file.
//
//go:build darwin && cgo
// +build darwin,cgo

package sensor

/*
#cgo CFLAGS: -x objective-c -fmodules -fblocks
#cgo LDFLAGS: -framework CoreFoundation -framework LocalAuthentication -framework Foundation -framework Security
#include <stdlib.h>
#include <stdio.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <Security/AuthSession.h>

int hasGUIAccess() {
    SecuritySessionId session;
    SessionAttributeBits attributes;
    OSStatus status = SessionGetInfo(callerSecuritySession, &session, &attributes);
    return status == errSecSuccess && (attributes & sessionHasGraphicAccess) != 0;
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

// HasGUIAccess reports whether this security session can display authentication UI.
func HasGUIAccess() bool {
	return C.hasGUIAccess() != 0
}
