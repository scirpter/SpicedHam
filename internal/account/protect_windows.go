//go:build windows

package account

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	cryptProtectData   = crypt32.NewProc("CryptProtectData")
	cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	localFree          = kernel32.NewProc("LocalFree")
	moveFileEx         = kernel32.NewProc("MoveFileExW")
	stateFileMagic     = []byte{'S', 'N', 'A', 'P', 'N', 'A', 'T', 0, 1}
)

type dataBlob struct {
	Length uint32
	Data   *byte
}

// DPAPI binds stored secrets to the real Windows user. Account-specific entropy
// additionally prevents a session file from being loaded as another account.
func protectState(plaintext, entropy []byte) ([]byte, error) {
	return transformState(cryptProtectData, plaintext, entropy, stateFileMagic)
}

func unprotectState(sealed, entropy []byte) ([]byte, error) {
	if len(sealed) <= len(stateFileMagic) || !bytes.Equal(sealed[:len(stateFileMagic)], stateFileMagic) {
		return nil, errors.New("unrecognized encrypted native state format")
	}
	return transformState(cryptUnprotectData, sealed[len(stateFileMagic):], entropy, nil)
}

func transformState(operation *syscall.LazyProc, source, entropy, prefix []byte) ([]byte, error) {
	if len(source) == 0 || uint64(len(source)) > 0xffffffff || uint64(len(entropy)) > 0xffffffff {
		return nil, errors.New("invalid DPAPI data size")
	}
	input := dataBlob{Length: uint32(len(source)), Data: unsafe.SliceData(source)}
	additional := dataBlob{Length: uint32(len(entropy)), Data: unsafe.SliceData(entropy)}
	var output dataBlob
	// CRYPTPROTECT_UI_FORBIDDEN; no UI or machine-wide secret binding.
	ok, _, callErr := operation.Call(
		uintptr(unsafe.Pointer(&input)), 0, uintptr(unsafe.Pointer(&additional)),
		0, 0, 1, uintptr(unsafe.Pointer(&output)),
	)
	runtime.KeepAlive(source)
	runtime.KeepAlive(entropy)
	runtime.KeepAlive(input)
	runtime.KeepAlive(additional)
	if ok == 0 {
		return nil, fmt.Errorf("%s: %w", operation.Name, callErr)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(output.Data)))
	if output.Data == nil || output.Length == 0 {
		return nil, errors.New("Windows DPAPI returned an empty result")
	}
	result := make([]byte, len(prefix)+int(output.Length))
	copy(result, prefix)
	nativeOutput := unsafe.Slice(output.Data, int(output.Length))
	copy(result[len(prefix):], nativeOutput)
	if operation == cryptUnprotectData {
		clear(nativeOutput)
	}
	return result, nil
}

func replaceStateFile(source, destination string) error {
	sourceUTF16, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationUTF16, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH, same filesystem.
	ok, _, callErr := moveFileEx.Call(uintptr(unsafe.Pointer(sourceUTF16)), uintptr(unsafe.Pointer(destinationUTF16)), 0x1|0x8)
	runtime.KeepAlive(sourceUTF16)
	runtime.KeepAlive(destinationUTF16)
	if ok == 0 {
		return fmt.Errorf("atomically replace encrypted native session: %w", callErr)
	}
	return nil
}
