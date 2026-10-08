//go:build windows && amd64

package armruntime

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	hostFileDescriptor = iota
	hostRandomDescriptor
	hostSocketDescriptor
)

type hostDescriptor struct {
	mu     sync.Mutex
	kind   int
	file   *os.File
	socket windows.Handle
	family int
	closed bool
}

func (d *hostDescriptor) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	switch d.kind {
	case hostFileDescriptor:
		return d.file.Close()
	case hostSocketDescriptor:
		return windows.Closesocket(d.socket)
	case hostRandomDescriptor:
		// crypto/rand is the actual shared Windows CSPRNG, not a guessed
		// device handle. Closing revokes this owned guest descriptor.
		return nil
	default:
		return errors.New("unknown owned host descriptor kind")
	}
}

type hostLinuxError struct {
	code      int
	operation string
}

func (e *hostLinuxError) Error() string {
	return fmt.Sprintf("actual host %s: Linux errno %d", e.operation, e.code)
}

func hostFileError(err error) (int, error) {
	var translated *hostLinuxError
	if errors.As(err, &translated) {
		return translated.code, nil
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return hostENOENT, nil
	case errors.Is(err, os.ErrPermission):
		return hostEACCES, nil
	case errors.Is(err, os.ErrExist):
		return hostEEXIST, nil
	case errors.Is(err, os.ErrClosed):
		return hostEBADF, nil
	case errors.Is(err, syscall.EINVAL):
		return hostEINVAL, nil
	case errors.Is(err, syscall.EBADF):
		return hostEBADF, nil
	case errors.Is(err, syscall.ENOTDIR):
		return hostENOTDIR, nil
	case errors.Is(err, syscall.EISDIR):
		return hostEISDIR, nil
	case errors.Is(err, syscall.ESPIPE):
		return hostESPIPE, nil
	case errors.Is(err, syscall.EAGAIN):
		return hostEAGAIN, nil
	}
	var code syscall.Errno
	if !errors.As(err, &code) {
		return 0, fmt.Errorf("actual host error lacks an audited Linux mapping: %w", err)
	}
	switch uint32(code) {
	case 1:
		return 38, nil
	case 2, 3, 18, 53, 67, 123:
		return hostENOENT, nil
	case 5, 32, 33, 65:
		return hostEACCES, nil
	case 6:
		return hostEBADF, nil
	case 8, 14:
		return hostENOMEM, nil
	case 19:
		return 30, nil
	case 21:
		return 19, nil
	case 23, 29, 30, 31:
		return 5, nil
	case 25:
		return hostESPIPE, nil
	case 39, 112:
		return 28, nil
	case 80, 183:
		return hostEEXIST, nil
	case 87, 131:
		return hostEINVAL, nil
	case 109, 232:
		return 32, nil
	case 145:
		return 39, nil
	case 206:
		return 36, nil
	case 267:
		return hostENOTDIR, nil
	case 995:
		return 4, nil
	case 10004:
		return 4, nil
	case 10009:
		return hostEBADF, nil
	case 10013:
		return hostEACCES, nil
	case 10014:
		return hostEFAULT, nil
	case 10022:
		return hostEINVAL, nil
	case 10024:
		return hostEMFILE, nil
	case 10035:
		return hostEAGAIN, nil
	case 10036:
		return 115, nil
	case 10037:
		return 114, nil
	case 10038:
		return hostENOTSOCK, nil
	case 10039:
		return 89, nil
	case 10040:
		return 90, nil
	case 10041:
		return 91, nil
	case 10042:
		return 92, nil
	case 10043:
		return 93, nil
	case 10044:
		return 94, nil
	case 10045:
		return 95, nil
	case 10046:
		return 96, nil
	case 10047:
		return 97, nil
	case 10048:
		return 98, nil
	case 10049:
		return 99, nil
	case 10050:
		return 100, nil
	case 10051:
		return 101, nil
	case 10052:
		return 102, nil
	case 10053:
		return 103, nil
	case 10054:
		return 104, nil
	case 10055:
		return 105, nil
	case 10056:
		return 106, nil
	case 10057, 10101:
		return 107, nil
	case 10058:
		return 108, nil
	case 10059:
		return 109, nil
	case 10060:
		return 110, nil
	case 10061:
		return 111, nil
	case 10062:
		return 40, nil
	case 10063:
		return 36, nil
	case 10064:
		return 112, nil
	case 10065:
		return 113, nil
	case 10066:
		return 39, nil
	case 10067:
		return hostEAGAIN, nil
	case 10068:
		return 87, nil
	case 10069:
		return 122, nil
	case 10070:
		return 116, nil
	case 10071:
		return 66, nil
	default:
		return 0, fmt.Errorf("actual Windows errno %d has no audited Linux mapping: %w", code, err)
	}
}

func hostFailure(err error) (uint64, error) {
	code, err := hostFileError(err)
	if err != nil {
		return 0, err
	}
	return hostNegative(code), nil
}

func (h *HostABI) addDescriptor(resource *hostDescriptor) (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for descriptor := uint64(3); descriptor <= math.MaxInt32; descriptor++ {
		if _, exists := h.descriptors[descriptor]; !exists {
			h.descriptors[descriptor] = resource
			return descriptor, nil
		}
	}
	return hostNegative(hostEMFILE), resource.close()
}

func (h *HostABI) descriptor(number uint64) *hostDescriptor {
	if number > math.MaxInt32 {
		return nil
	}
	h.mu.Lock()
	resource := h.descriptors[number]
	h.mu.Unlock()
	return resource
}

func (h *HostABI) closeDescriptor(number uint64) (uint64, error) {
	h.mu.Lock()
	resource := h.descriptors[number]
	if resource != nil {
		delete(h.descriptors, number)
	}
	h.mu.Unlock()
	if resource == nil {
		return hostNegative(hostEBADF), nil
	}
	if err := resource.close(); err != nil {
		return hostFailure(err)
	}
	return 0, nil
}

func hostAbsolute(path string) bool {
	return filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\")
}

func hostHandlePath(handle windows.Handle) (string, error) {
	var initial [512]uint16
	length, err := windows.GetFinalPathNameByHandle(handle, &initial[0], uint32(len(initial)), 0)
	if err != nil {
		return "", err
	}
	if length < uint32(len(initial)) {
		return windows.UTF16ToString(initial[:length]), nil
	}
	if length > 32767 {
		return "", errors.New("actual host file path exceeds the Windows path bound")
	}
	buffer := make([]uint16, length+1)
	length, err = windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil {
		return "", err
	}
	if length >= uint32(len(buffer)) {
		return "", errors.New("actual host file path changed beyond its owned buffer")
	}
	return windows.UTF16ToString(buffer[:length]), nil
}

func (h *HostABI) filePath(directory uint64, path string) (string, error) {
	if path == "" {
		return "", &hostLinuxError{hostENOENT, "empty path"}
	}
	if int32(directory) == -100 || hostAbsolute(path) {
		return path, nil
	}
	resource := h.descriptor(uint64(uint32(directory)))
	if resource == nil {
		return "", &hostLinuxError{hostEBADF, "relative directory descriptor"}
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closed || resource.kind != hostFileDescriptor {
		return "", &hostLinuxError{hostEBADF, "relative directory descriptor"}
	}
	info, err := resource.file.Stat()
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", &hostLinuxError{hostENOTDIR, "relative directory descriptor"}
	}
	parent, err := hostHandlePath(windows.Handle(resource.file.Fd()))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, path), nil
}

func (h *HostABI) openAt(a [8]uint64) (uint64, error) {
	path, err := h.cString(a[1])
	if err != nil {
		return hostNegative(hostEFAULT), nil
	}
	flags := a[2]
	const allowed = uint64(3 | 64 | 128 | 512 | 1024 | 2048 | 0x4000 | 0x20000 | 0x80000)
	if flags&^allowed != 0 {
		return 0, fmt.Errorf("unsupported original ARM64 openat flags %#x", flags)
	}
	if flags&3 == 3 {
		return hostNegative(hostEINVAL), nil
	}
	if path == "/dev/urandom" {
		if flags&0x4000 != 0 {
			return hostNegative(hostENOTDIR), nil
		}
		if flags&3 != 0 {
			return hostNegative(hostEACCES), nil
		}
		if flags&(64|128) == 64|128 {
			return hostNegative(hostEEXIST), nil
		}
		return h.addDescriptor(&hostDescriptor{kind: hostRandomDescriptor})
	}
	path, err = h.filePath(a[0], path)
	if err != nil {
		return hostFailure(err)
	}
	if flags&0x4000 != 0 {
		info, err := os.Stat(path)
		if err != nil {
			return hostFailure(err)
		}
		if !info.IsDir() {
			return hostNegative(hostENOTDIR), nil
		}
		if flags&3 != 0 {
			return hostNegative(hostEISDIR), nil
		}
	}
	mode := os.O_RDONLY
	switch flags & 3 {
	case 1:
		mode = os.O_WRONLY
	case 2:
		mode = os.O_RDWR
	}
	for _, translation := range [...]struct {
		guest  uint64
		native int
	}{
		{64, os.O_CREATE}, {128, os.O_EXCL}, {512, os.O_TRUNC}, {1024, os.O_APPEND},
	} {
		if flags&translation.guest != 0 {
			mode |= translation.native
		}
	}
	file, err := os.OpenFile(path, mode, os.FileMode(a[3]&0777))
	if err != nil {
		return hostFailure(err)
	}
	return h.addDescriptor(&hostDescriptor{kind: hostFileDescriptor, file: file})
}

func (h *HostABI) readDescriptor(a [8]uint64) (uint64, error) {
	resource := h.descriptor(a[0])
	if resource == nil {
		return hostNegative(hostEBADF), nil
	}
	length := min(a[2], hostMaxIO)
	if err := h.validateRange(a[1], length); err != nil {
		return hostNegative(hostEFAULT), nil
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closed {
		return hostNegative(hostEBADF), nil
	}
	if length == 0 {
		return 0, nil
	}
	if resource.kind == hostFileDescriptor {
		info, err := resource.file.Stat()
		if err != nil {
			return hostFailure(err)
		}
		if info.IsDir() {
			return hostNegative(hostEISDIR), nil
		}
	}
	var scratch [65536]byte
	var copied uint64
	for copied < length {
		amount := min(length-copied, uint64(len(scratch)))
		var count int
		var err error
		switch resource.kind {
		case hostRandomDescriptor:
			count, err = io.ReadFull(rand.Reader, scratch[:amount])
		case hostFileDescriptor:
			count, err = resource.file.Read(scratch[:amount])
		case hostSocketDescriptor:
			count, _, err = windows.Recvfrom(resource.socket, scratch[:amount], 0)
		default:
			return 0, errors.New("unknown owned host read descriptor")
		}
		if count != 0 {
			if writeErr := h.writeMemory(a[1]+copied, scratch[:count]); writeErr != nil {
				if copied != 0 {
					return copied, nil
				}
				return hostNegative(hostEFAULT), nil
			}
			copied += uint64(count)
		}
		if err != nil {
			if copied != 0 || errors.Is(err, io.EOF) {
				return copied, nil
			}
			return hostFailure(err)
		}
		if count == 0 || uint64(count) < amount || resource.kind == hostSocketDescriptor {
			return copied, nil
		}
	}
	return copied, nil
}

func (h *HostABI) seekDescriptor(a [8]uint64) (uint64, error) {
	resource := h.descriptor(a[0])
	if resource == nil {
		return hostNegative(hostEBADF), nil
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closed {
		return hostNegative(hostEBADF), nil
	}
	if resource.kind != hostFileDescriptor {
		return hostNegative(hostESPIPE), nil
	}
	if a[2] > 2 {
		return hostNegative(hostEINVAL), nil
	}
	offset, err := resource.file.Seek(int64(a[1]), int(a[2]))
	if err != nil {
		return hostFailure(err)
	}
	return uint64(offset), nil
}

func (h *HostABI) openSocket(a [8]uint64) (uint64, error) {
	family := int(a[0])
	switch a[0] {
	case 1:
		family = windows.AF_UNIX
	case 2:
		family = windows.AF_INET
	case 10:
		family = windows.AF_INET6
	default:
		return 0, fmt.Errorf("unsupported guest socket domain %d", a[0])
	}
	if a[1]&^uint64(0xf|0x800|0x80000) != 0 {
		return 0, fmt.Errorf("unsupported guest socket type flags %#x", a[1])
	}
	if a[2] > math.MaxInt32 {
		return hostNegative(hostEINVAL), nil
	}
	h.mu.Lock()
	if !h.winsockStarted {
		var data windows.WSAData
		if err := windows.WSAStartup(0x202, &data); err != nil {
			h.mu.Unlock()
			return 0, fmt.Errorf("start actual Winsock: %w", err)
		}
		h.winsockStarted = true
	}
	h.mu.Unlock()
	socket, err := windows.Socket(family, int(a[1]&0xf), int(a[2]))
	if err != nil {
		return hostFailure(err)
	}
	if err := windows.SetHandleInformation(socket, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		return 0, errors.Join(err, windows.Closesocket(socket))
	}
	if a[1]&0x800 != 0 {
		if err := hostSocketLastError.Find(); err != nil {
			return 0, errors.Join(err, windows.Closesocket(socket))
		}
		if err := hostSocketIoctl.Find(); err != nil {
			return 0, errors.Join(err, windows.Closesocket(socket))
		}
		var nonblocking uint32 = 1
		runtime.LockOSThread()
		result, _, _ := hostSocketIoctl.Call(uintptr(socket), 0x8004667e, uintptr(unsafe.Pointer(&nonblocking)))
		var socketErr error
		if int32(result) == -1 {
			code, _, _ := hostSocketLastError.Call()
			socketErr = syscall.Errno(code)
		}
		runtime.UnlockOSThread()
		if socketErr != nil {
			closeErr := windows.Closesocket(socket)
			if closeErr != nil {
				return 0, errors.Join(socketErr, closeErr)
			}
			return hostFailure(socketErr)
		}
	}
	return h.addDescriptor(&hostDescriptor{kind: hostSocketDescriptor, socket: socket, family: family})
}

func (h *HostABI) bindSocket(a [8]uint64) (uint64, error) {
	resource := h.descriptor(a[0])
	if resource == nil {
		return hostNegative(hostEBADF), nil
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closed {
		return hostNegative(hostEBADF), nil
	}
	if resource.kind != hostSocketDescriptor {
		return hostNegative(hostENOTSOCK), nil
	}
	if a[2] < 2 || a[2] > 128 {
		return hostNegative(hostEINVAL), nil
	}
	var address [128]byte
	if err := h.readMemory(a[1], address[:a[2]]); err != nil {
		return hostNegative(hostEFAULT), nil
	}
	family := binary.LittleEndian.Uint16(address[:2])
	switch family {
	case 1:
		if a[2] > 110 || resource.family != windows.AF_UNIX {
			return hostNegative(hostEINVAL), nil
		}
		// Pass the actual pathname/abstract sockaddr_un to Windows. Its real
		// success/failure is retained; no Android service is created here.
	case 2:
		if a[2] < 16 || resource.family != windows.AF_INET {
			return hostNegative(hostEINVAL), nil
		}
	case 10:
		if a[2] < 28 || resource.family != windows.AF_INET6 {
			return hostNegative(hostEINVAL), nil
		}
		binary.LittleEndian.PutUint16(address[:2], windows.AF_INET6)
	default:
		return 0, fmt.Errorf("unsupported guest bind sockaddr family %d", family)
	}
	if err := hostSocketBind.Find(); err != nil {
		return 0, err
	}
	if err := hostSocketLastError.Find(); err != nil {
		return 0, err
	}
	runtime.LockOSThread()
	result, _, _ := hostSocketBind.Call(uintptr(resource.socket), uintptr(unsafe.Pointer(&address[0])), uintptr(a[2]))
	var err error
	if int32(result) == -1 {
		code, _, _ := hostSocketLastError.Call()
		err = syscall.Errno(code)
	}
	runtime.UnlockOSThread()
	runtime.KeepAlive(address)
	if err != nil {
		return hostFailure(err)
	}
	return 0, nil
}

// This is the installed Windows AMD64 UCRT _stat64 record, not ARM64 stat.
type hostCRTStat struct {
	device   uint32
	inode    uint16
	mode     uint16
	links    int16
	uid      int16
	gid      int16
	_        uint16
	rdev     uint32
	_        uint32
	size     int64
	access   int64
	modified int64
	created  int64
}

type hostBasicFileInfo struct {
	created    int64
	access     int64
	modified   int64
	changed    int64
	attributes uint32
	_          uint32
}

type hostStandardFileInfo struct {
	allocation    int64
	size          int64
	links         uint32
	deletePending uint8
	directory     uint8
	_             uint16
}

func (h *HostABI) crtFileStat(path string) (hostCRTStat, error) {
	var record hostCRTStat
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return record, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pointer, _, _ := syscall.SyscallN(h.crt.errno)
	if pointer == 0 {
		return record, errors.New("actual UCRT stat errno pointer is null")
	}
	nativeErrno := (*int32)(unsafe.Pointer(pointer))
	previous := *nativeErrno
	*nativeErrno = 0
	defer func() { *nativeErrno = previous }()
	result, _, _ := syscall.SyscallN(h.crt.stat, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&record)))
	runtime.KeepAlive(name)
	runtime.KeepAlive(&record)
	if int32(result) != 0 {
		code, err := hostCRTError(int(*nativeErrno))
		if err != nil {
			return record, err
		}
		return record, &hostLinuxError{code, "UCRT _wstat64"}
	}
	return record, nil
}

func hostFileTime(ticks int64) (int64, uint64) {
	ticks -= 116444736000000000
	seconds, remainder := ticks/10000000, ticks%10000000
	if remainder < 0 {
		seconds--
		remainder += 10000000
	}
	return seconds, uint64(remainder) * 100
}

func hostFileBlockSize(path string) (uint32, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var initial [512]uint16
	volume := initial[:]
	err = windows.GetVolumePathName(name, &volume[0], uint32(len(volume)))
	if err != nil && len(path)+1 > len(volume) && len(path)+1 <= 32768 &&
		(errors.Is(err, windows.ERROR_MORE_DATA) || errors.Is(err, windows.ERROR_FILENAME_EXCED_RANGE)) {
		volume = make([]uint16, len(path)+1)
		err = windows.GetVolumePathName(name, &volume[0], uint32(len(volume)))
	}
	if err != nil {
		return 0, err
	}
	if err := hostDiskFreeSpace.Find(); err != nil {
		return 0, err
	}
	var sectors, bytes, freeClusters, clusters uint32
	ok, _, callErr := hostDiskFreeSpace.Call(uintptr(unsafe.Pointer(&volume[0])), uintptr(unsafe.Pointer(&sectors)), uintptr(unsafe.Pointer(&bytes)), uintptr(unsafe.Pointer(&freeClusters)), uintptr(unsafe.Pointer(&clusters)))
	if ok == 0 {
		return 0, callErr
	}
	block := uint64(sectors) * uint64(bytes)
	if block == 0 || block > math.MaxInt32 {
		return 0, errors.New("actual host filesystem allocation unit exceeds ARM64 stat block-size range")
	}
	return uint32(block), nil
}

func (h *HostABI) fileStatRecord(path string, handle windows.Handle, nofollow bool) ([128]byte, error) {
	var output [128]byte
	actualPath, err := hostHandlePath(handle)
	if err != nil {
		return output, err
	}
	path = actualPath
	crt, err := h.crtFileStat(path)
	if err != nil {
		return output, err
	}
	var identity windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil {
		return output, err
	}
	var basic hostBasicFileInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return output, err
	}
	var standard hostStandardFileInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileStandardInfo, (*byte)(unsafe.Pointer(&standard)), uint32(unsafe.Sizeof(standard))); err != nil {
		return output, err
	}
	if standard.size < 0 || standard.allocation < 0 || standard.allocation > math.MaxInt64-511 {
		return output, errors.New("actual host file returned invalid size/allocation metadata")
	}
	blockSize, err := hostFileBlockSize(path)
	if err != nil {
		return output, err
	}
	mode := uint32(crt.mode)
	size := standard.size
	if nofollow {
		info, err := os.Lstat(path)
		if err != nil {
			return output, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return output, err
			}
			mode = mode&07777 | 0120000
			size = int64(len(target))
		}
	}
	// ARM64 asm-generic/stat.h is 128 bytes. Metadata is translated from
	// actual Win32 handles/filesystem and UCRT permission/UID/GID semantics.
	// UCRT documents its Windows UID/GID fields as zero: these are genuine
	// host portability results, not an Android application identity.
	binary.LittleEndian.PutUint64(output[0:], uint64(identity.VolumeSerialNumber))
	binary.LittleEndian.PutUint64(output[8:], uint64(identity.FileIndexHigh)<<32|uint64(identity.FileIndexLow))
	binary.LittleEndian.PutUint32(output[16:], mode)
	binary.LittleEndian.PutUint32(output[20:], standard.links)
	binary.LittleEndian.PutUint32(output[24:], uint32(uint16(crt.uid)))
	binary.LittleEndian.PutUint32(output[28:], uint32(uint16(crt.gid)))
	binary.LittleEndian.PutUint64(output[32:], uint64(crt.rdev))
	binary.LittleEndian.PutUint64(output[48:], uint64(size))
	binary.LittleEndian.PutUint32(output[56:], blockSize)
	binary.LittleEndian.PutUint64(output[64:], uint64((standard.allocation+511)/512))
	for _, field := range [...]struct {
		offset int
		ticks  int64
	}{
		{72, basic.access}, {88, basic.modified}, {104, basic.changed},
	} {
		seconds, nanoseconds := hostFileTime(field.ticks)
		binary.LittleEndian.PutUint64(output[field.offset:], uint64(seconds))
		binary.LittleEndian.PutUint64(output[field.offset+8:], nanoseconds)
	}
	return output, nil
}

func (h *HostABI) statAt(a [8]uint64) (uint64, error) {
	if a[3]&^uint64(0x100) != 0 {
		return 0, fmt.Errorf("unsupported original ARM64 newfstatat flags %#x", a[3])
	}
	path, err := h.cString(a[1])
	if err != nil {
		return hostNegative(hostEFAULT), nil
	}
	path, err = h.filePath(a[0], path)
	if err != nil {
		return hostFailure(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return hostFailure(err)
	}
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if a[3]&0x100 != 0 {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return hostFailure(err)
	}
	record, err := h.fileStatRecord(path, handle, a[3]&0x100 != 0)
	closeErr := windows.CloseHandle(handle)
	if err != nil {
		if closeErr != nil {
			return 0, errors.Join(err, closeErr)
		}
		return hostFailure(err)
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if err := h.writeMemory(a[2], record[:]); err != nil {
		return hostNegative(hostEFAULT), nil
	}
	return 0, nil
}

func (h *HostABI) statDescriptor(a [8]uint64) (uint64, error) {
	resource := h.descriptor(a[0])
	if resource == nil {
		return hostNegative(hostEBADF), nil
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closed {
		return hostNegative(hostEBADF), nil
	}
	if resource.kind != hostFileDescriptor {
		return 0, errors.New("actual CSPRNG/socket descriptor has no Linux device-stat record; none fabricated")
	}
	handle := windows.Handle(resource.file.Fd())
	path, err := hostHandlePath(handle)
	if err != nil {
		return hostFailure(err)
	}
	record, err := h.fileStatRecord(path, handle, false)
	if err != nil {
		return hostFailure(err)
	}
	if err := h.writeMemory(a[1], record[:]); err != nil {
		return hostNegative(hostEFAULT), nil
	}
	return 0, nil
}

type hostIOVector struct {
	address uint64
	length  uint64
}

func (h *HostABI) ioVectors(address, count uint64) ([]hostIOVector, uint64, error) {
	if count > 1024 {
		return nil, 0, &hostLinuxError{hostEINVAL, "process_vm_readv iovec count"}
	}
	if count == 0 {
		return nil, 0, nil
	}
	var raw [16384]byte
	if err := h.readMemory(address, raw[:count*16]); err != nil {
		return nil, 0, &hostLinuxError{hostEFAULT, "process_vm_readv iovec array"}
	}
	vectors := make([]hostIOVector, count)
	var total uint64
	for index := range vectors {
		vector := raw[index*16:]
		pointer := binary.LittleEndian.Uint64(vector)
		length := binary.LittleEndian.Uint64(vector[8:])
		if length > math.MaxInt64-total || pointer > math.MaxUint64-length {
			return nil, 0, &hostLinuxError{hostEINVAL, "process_vm_readv iovec range"}
		}
		vectors[index] = hostIOVector{pointer, length}
		total += length
	}
	return vectors, total, nil
}

func (h *HostABI) processRead(a [8]uint64) (uint64, error) {
	if a[0] != uint64(os.Getpid()) {
		return 0, errors.New("original process_vm_readv may target only the actual self PID and genuine guest memory")
	}
	if a[5] != 0 || a[2] > 1024 || a[4] > 1024 {
		return hostNegative(hostEINVAL), nil
	}
	local, localLength, err := h.ioVectors(a[1], a[2])
	if err != nil {
		return hostFailure(err)
	}
	remote, remoteLength, err := h.ioVectors(a[3], a[4])
	if err != nil {
		return hostFailure(err)
	}
	wanted := min(localLength, remoteLength)
	var copied, localOffset, remoteOffset uint64
	var localIndex, remoteIndex int
	var scratch [4096]byte
	for copied < wanted {
		for localIndex < len(local) && localOffset == local[localIndex].length {
			localIndex++
			localOffset = 0
		}
		for remoteIndex < len(remote) && remoteOffset == remote[remoteIndex].length {
			remoteIndex++
			remoteOffset = 0
		}
		amount := min(wanted-copied, uint64(len(scratch)), local[localIndex].length-localOffset, remote[remoteIndex].length-remoteOffset)
		if err := h.readMemory(remote[remoteIndex].address+remoteOffset, scratch[:amount]); err != nil {
			if copied != 0 {
				return copied, nil
			}
			return hostNegative(hostEFAULT), nil
		}
		if err := h.writeMemory(local[localIndex].address+localOffset, scratch[:amount]); err != nil {
			if copied != 0 {
				return copied, nil
			}
			return hostNegative(hostEFAULT), nil
		}
		copied += amount
		localOffset += amount
		remoteOffset += amount
	}
	return copied, nil
}

func (h *HostABI) getTimeOfDay(a [8]uint64) (uint64, error) {
	if a[0] != 0 {
		var clock windows.Filetime
		windows.GetSystemTimePreciseAsFileTime(&clock)
		ticks := uint64(clock.HighDateTime)<<32 | uint64(clock.LowDateTime)
		if ticks < 116444736000000000 {
			return 0, errors.New("actual wall clock predates Unix epoch")
		}
		ticks -= 116444736000000000
		var value [16]byte
		binary.LittleEndian.PutUint64(value[:8], ticks/10000000)
		binary.LittleEndian.PutUint64(value[8:], ticks%10000000/10)
		if err := h.writeMemory(a[0], value[:]); err != nil {
			return hostNegative(hostEFAULT), nil
		}
	}
	if a[1] != 0 {
		var zone windows.Timezoneinformation
		if _, err := windows.GetTimeZoneInformation(&zone); err != nil {
			return hostFailure(err)
		}
		var value [8]byte
		binary.LittleEndian.PutUint32(value[:4], uint32(zone.Bias+zone.StandardBias))
		if zone.DaylightDate.Month != 0 {
			binary.LittleEndian.PutUint32(value[4:], 1)
		}
		if err := h.writeMemory(a[1], value[:]); err != nil {
			return hostNegative(hostEFAULT), nil
		}
	}
	return 0, nil
}

func (h *HostABI) Syscall(number uint64, a [8]uint64) (uint64, error) {
	if err := h.usable(); err != nil {
		return 0, err
	}
	switch number {
	case 56:
		return h.openAt(a)
	case 57:
		return h.closeDescriptor(a[0])
	case 62:
		return h.seekDescriptor(a)
	case 63:
		return h.readDescriptor(a)
	case 79:
		return h.statAt(a)
	case 80:
		return h.statDescriptor(a)
	case 113:
		return h.clockTime(a[0], a[1])
	case 169:
		return h.getTimeOfDay(a)
	case 172:
		return uint64(os.Getpid()), nil
	case 178:
		return uint64(windows.GetCurrentThreadId()), nil
	case 270:
		return h.processRead(a)
	default:
		return 0, fmt.Errorf("unsupported original ARM64 Linux syscall %d", number)
	}
}
