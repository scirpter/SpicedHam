//go:build windows

package armruntime

import (
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// AOSP libbase's non-Bionic property map, not an Android property daemon.
// No build, boot, device, attestation, or environment values are seeded.
// JNI modified UTF-8 is retained verbatim, including its byte-limit semantics.
// https://android.googlesource.com/platform/system/libbase/+/refs/tags/android-13.0.0_r1/properties.cpp
// https://android.googlesource.com/platform/system/libbase/+/refs/tags/android-13.0.0_r1/parsebool.cpp
// https://android.googlesource.com/platform/system/libbase/+/refs/tags/android-13.0.0_r1/include/android-base/parseint.h
// https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-13.0.0_r1/core/jni/android_os_SystemProperties.cpp

type hostPropertyValue struct {
	key   string
	bytes string // Owned, immutable, and NUL-terminated for original NewStringUTF.
}

type hostPropertyStore struct {
	mu     sync.RWMutex
	values map[string]hostPropertyValue
}

func (p *hostPropertyStore) get(key string) string {
	p.mu.RLock()
	value := p.values[key].bytes
	p.mu.RUnlock()
	return value
}

func (p *hostPropertyStore) set(key, value string) bool {
	if key == "" || (!strings.HasPrefix(key, "ro.") && len(value) >= 92) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	previous, exists := p.values[key]
	if exists && strings.HasPrefix(key, "ro.") {
		return false
	}
	if previous.bytes != "" && previous.bytes[:len(previous.bytes)-1] == value {
		return true
	}
	if !exists {
		previous.key = strings.Clone(key) // JNI owns the borrowed input key.
	}
	previous.bytes = value + "\x00" // One required lifetime copy; getters borrow it.
	if p.values == nil {
		p.values = make(map[string]hostPropertyValue)
	}
	p.values[previous.key] = previous
	return true
}

func hostPropertyInteger(value string, bits int) (int64, bool) {
	// Original ParseInt skips leading C whitespace but rejects trailing bytes;
	// only an initial 0x selects hex. A leading zero is NOT octal.
	value = strings.TrimLeft(value, " \t\r\n\v\f")
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		value = value[2:]
		// strtoll accepts a sign before, not inside, its hexadecimal prefix.
		if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
			return 0, false
		}
	}
	number, err := strconv.ParseInt(value, base, bits)
	return number, err == nil
}

func (j *JVM) propertyDispatch(environment, operation, address, length, other, otherLength uintptr) uintptr {
	if address == 0 || length > uintptr(^uint32(0)>>1) {
		throwNativeJavaException(environment, errors.New("invalid actual JNI property key range"))
		return 0
	}
	key := unsafe.String((*byte)(unsafe.Pointer(address)), int(length))
	if operation == 5 {
		if otherLength > uintptr(^uint32(0)>>1) || (other == 0 && otherLength != 0) {
			throwNativeJavaException(environment, errors.New("invalid actual JNI property value range"))
			return 0
		}
		var value string
		if otherLength != 0 {
			value = unsafe.String((*byte)(unsafe.Pointer(other)), int(otherLength))
		}
		if j.properties.set(key, value) {
			return 1
		}
		return 0
	}
	terminated := j.properties.get(key)
	var value string
	if terminated != "" {
		value = terminated[:len(terminated)-1]
	}
	switch operation {
	case 1:
		if value == "" && other != 0 {
			return other // Preserve the actual Java default object.
		}
		if value == "" {
			terminated = "\x00" // Original JNI legacy get(key, null) yields empty.
		}
		table := *(*uintptr)(unsafe.Pointer(environment))
		function := *(*uintptr)(unsafe.Pointer(table + 167*unsafe.Sizeof(uintptr(0))))
		result, _, _ := syscall.SyscallN(function, environment, uintptr(unsafe.Pointer(unsafe.StringData(terminated))))
		runtime.KeepAlive(terminated)
		return result
	case 2, 3:
		bits := 64
		if operation == 2 {
			bits = 32
		}
		if number, ok := hostPropertyInteger(value, bits); ok {
			return uintptr(number)
		}
		return other
	case 4:
		switch value {
		case "1", "y", "yes", "on", "true":
			return 1
		case "0", "n", "no", "off", "false":
			return 0
		default:
			return other
		}
	default:
		throwNativeJavaException(environment, errors.New("unsupported actual host property operation"))
		return 0
	}
}
