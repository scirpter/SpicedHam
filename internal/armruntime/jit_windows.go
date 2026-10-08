//go:build windows && amd64

package armruntime

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var protectMemory = kernel32.NewProc("VirtualProtect")
var allocateNativeMemory = kernel32.NewProc("VirtualAlloc")

// Unicorn reserves RWX JIT pages and normally commits them through an expected
// access violation. Make this CPU library's own requested JIT allocation
// accessible eagerly; no exception or guest/native validation is suppressed.
var allocateAccessibleNativeJIT = syscall.NewCallback(func(address, size, allocationType, protection uintptr) uintptr {
	if allocationType == 0x2000 && protection == 0x40 {
		allocationType |= 0x1000
	}
	result, _, _ := allocateNativeMemory.Call(address, size, allocationType, protection)
	return result
})

func importSlot(path, symbol string) (uint32, error) {
	image, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	file, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return 0, err
	}
	header, ok := file.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || file.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return 0, errors.New("native CPU runtime must be a Windows AMD64 DLL")
	}
	at := func(rva uint32, size uint32) ([]byte, error) {
		for _, section := range file.Sections {
			if rva < section.VirtualAddress || rva-section.VirtualAddress >= section.Size {
				continue
			}
			offset := uint64(section.Offset) + uint64(rva-section.VirtualAddress)
			if offset > uint64(len(image)) || uint64(size) > uint64(len(image))-offset {
				return nil, errors.New("native CPU import data exceeds file")
			}
			return image[offset : offset+uint64(size)], nil
		}
		return nil, fmt.Errorf("native CPU import RVA %x is unmapped", rva)
	}
	readString := func(rva uint32) (string, error) {
		var value []byte
		for count := uint32(0); count < 256; count++ {
			part, err := at(rva+count, 1)
			if err != nil {
				return "", err
			}
			if part[0] == 0 {
				return string(value), nil
			}
			value = append(value, part[0])
		}
		return "", errors.New("unterminated CPU-runtime import name")
	}
	directory := header.DataDirectory[1]
	for offset := uint32(0); offset+20 <= directory.Size; offset += 20 {
		descriptor, err := at(directory.VirtualAddress+offset, 20)
		if err != nil {
			return 0, err
		}
		lookup := binary.LittleEndian.Uint32(descriptor)
		address := binary.LittleEndian.Uint32(descriptor[16:])
		if lookup == 0 && address == 0 {
			break
		}
		if lookup == 0 {
			lookup = address
		}
		for index := uint32(0); index < 4096; index++ {
			entry, err := at(lookup+index*8, 8)
			if err != nil {
				return 0, err
			}
			nameRVA := binary.LittleEndian.Uint64(entry)
			if nameRVA == 0 {
				break
			}
			if nameRVA>>63 != 0 {
				continue
			}
			if nameRVA > 0xffffffff-2 {
				return 0, errors.New("invalid CPU-runtime import-name RVA")
			}
			name, err := readString(uint32(nameRVA) + 2)
			if err != nil {
				return 0, err
			}
			if name == symbol {
				return address + index*8, nil
			}
		}
	}
	return 0, fmt.Errorf("genuine native CPU runtime import %s not found", symbol)
}

func replaceImport(address uintptr, value uintptr) error {
	var priorProtection uint32
	ok, _, callErr := protectMemory.Call(address, unsafe.Sizeof(uintptr(0)), 4, uintptr(unsafe.Pointer(&priorProtection)))
	if ok == 0 {
		return callErr
	}
	*(*uintptr)(unsafe.Pointer(address)) = value
	var discarded uint32
	ok, _, callErr = protectMemory.Call(address, unsafe.Sizeof(uintptr(0)), uintptr(priorProtection), uintptr(unsafe.Pointer(&discarded)))
	runtime.KeepAlive(&priorProtection)
	runtime.KeepAlive(&discarded)
	if ok == 0 {
		return callErr
	}
	return nil
}

func installNativeJITAllocator(c *cpuRuntime, path string) (func() error, error) {
	slot, err := importSlot(path, "VirtualAlloc")
	if err != nil {
		return nil, err
	}
	address := uintptr(c.dll.Handle) + uintptr(slot)
	original := *(*uintptr)(unsafe.Pointer(address))
	if err := replaceImport(address, allocateAccessibleNativeJIT); err != nil {
		return nil, err
	}
	return func() error { return replaceImport(address, original) }, nil
}
