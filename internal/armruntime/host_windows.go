//go:build windows && amd64

package armruntime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	hostEPERM    = 1
	hostENOENT   = 2
	hostEBADF    = 9
	hostENOMEM   = 12
	hostEACCES   = 13
	hostEFAULT   = 14
	hostEBUSY    = 16
	hostEEXIST   = 17
	hostENOTDIR  = 20
	hostEISDIR   = 21
	hostEINVAL   = 22
	hostEMFILE   = 24
	hostESPIPE   = 29
	hostEAGAIN   = 11
	hostEDEADLK  = 35
	hostENOTSOCK = 88
	hostMaxIO    = uint64(0x7ffff000)
)

var (
	hostKernel = windows.NewLazySystemDLL("kernel32.dll")
	// Both genuine Windows boot clocks use the realtime API set. Linux clock 1
	// excludes suspension; QPC includes it and must not supply CLOCK_MONOTONIC.
	hostRealtime        = windows.NewLazySystemDLL("api-ms-win-core-realtime-l1-1-2.dll")
	hostUnbiasedTime    = hostRealtime.NewProc("QueryUnbiasedInterruptTimePrecise")
	hostInterruptTime   = hostRealtime.NewProc("QueryInterruptTimePrecise")
	hostDiskFreeSpace   = hostKernel.NewProc("GetDiskFreeSpaceW")
	hostWinsock         = windows.NewLazySystemDLL("ws2_32.dll")
	hostSocketBind      = hostWinsock.NewProc("bind")
	hostSocketIoctl     = hostWinsock.NewProc("ioctlsocket")
	hostSocketLastError = hostWinsock.NewProc("WSAGetLastError")
)

type hostCRT struct {
	library  windows.Handle
	errno    uintptr
	strtoll  uintptr
	strtoull uintptr
	atoi     uintptr
	stat     uintptr
	exit     uintptr
}

type hostExitCallback struct {
	function uint64
	argument uint64
	dso      uint64
}

// HostABI owns the host resources behind the original ARM64 imports. Addresses
// crossing this boundary are guest addresses, never native Windows pointers.
// Android properties and dynamic Android libraries are not initialized here.
type HostABI struct {
	memory    GuestMemory
	auxiliary map[uint64]uint64
	crt       hostCRT

	mu              sync.Mutex
	closing         bool
	closed          bool
	closeError      error
	execute         func(uint64, [8]uint64) (uint64, error)
	callbacks       []hostExitCallback
	allocations     map[uint64]hostAllocation
	allocationOrder []uint64
	hostData        map[string]uint64
	loaderErrors    map[uint64]string
	loaderBuffers   map[uint64]uint64
	descriptors     map[uint64]*hostDescriptor
	winsockStarted  bool
	mutexes         map[uint64]*hostMutex
	conditions      map[uint64]*hostCondition
}

func NewHostABI(memory GuestMemory, auxiliary map[uint64]uint64) (_ *HostABI, err error) {
	if memory == nil {
		return nil, errors.New("host ABI requires the actual guest memory boundary")
	}
	library, err := windows.LoadLibraryEx("ucrtbase.dll", 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("load genuine host UCRT: %w", err)
	}
	h := &HostABI{
		memory:        memory,
		auxiliary:     make(map[uint64]uint64, len(auxiliary)),
		crt:           hostCRT{library: library},
		allocations:   make(map[uint64]hostAllocation),
		hostData:      make(map[string]uint64),
		loaderErrors:  make(map[uint64]string),
		loaderBuffers: make(map[uint64]uint64),
		descriptors:   make(map[uint64]*hostDescriptor),
		mutexes:       make(map[uint64]*hostMutex),
		conditions:    make(map[uint64]*hostCondition),
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, windows.FreeLibrary(library))
		}
	}()
	for _, function := range [...]struct {
		name   string
		target *uintptr
	}{
		{"_errno", &h.crt.errno},
		{"strtoll", &h.crt.strtoll},
		{"strtoull", &h.crt.strtoull},
		{"atoi", &h.crt.atoi},
		{"_wstat64", &h.crt.stat},
		{"exit", &h.crt.exit},
	} {
		*function.target, err = windows.GetProcAddress(library, function.name)
		if err != nil {
			return nil, fmt.Errorf("resolve genuine UCRT %s: %w", function.name, err)
		}
	}
	if err = hostUnbiasedTime.Find(); err != nil {
		return nil, fmt.Errorf("resolve actual suspension-excluding monotonic clock: %w", err)
	}
	for key, value := range auxiliary {
		h.auxiliary[key] = value
	}
	return h, nil
}

// SetGuestExecutor lets the owning CPU execute original guest destructors. The
// CPU and JVM must remain alive until HostABI.Close has completed.
func (h *HostABI) SetGuestExecutor(execute func(uint64, [8]uint64) (uint64, error)) {
	h.mu.Lock()
	h.execute = execute
	h.mu.Unlock()
}

func (h *HostABI) usable() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("host ABI is closed")
	}
	return nil
}

func (h *HostABI) Invoke(name string, a [8]uint64) (uint64, error) {
	if err := h.usable(); err != nil {
		return 0, err
	}
	switch name {
	case "strtoll", "strtoull", "atoi":
		return h.convertNumber(name, a)
	case "malloc":
		return h.malloc(a[0], false)
	case "calloc":
		if a[0] != 0 && a[1] > math.MaxUint64/a[0] {
			return 0, h.setErrno(hostENOMEM)
		}
		return h.malloc(a[0]*a[1], true)
	case "free":
		return 0, h.releaseAllocation(a[0], false)
	case "realloc":
		return h.realloc(a[0], a[1])
	case "memset":
		return a[0], h.fill(a[0], a[2], byte(a[1]))
	case "memcpy", "memmove":
		return a[0], h.copyMemory(a[0], a[1], a[2], name == "memmove")
	case "pthread_create":
		if a[1] != 0 {
			return 0, errors.New("guest pthread attributes require an original bionic layout adapter")
		}
		return h.memory.CreateGuestThread(a)
	case "pthread_join":
		return h.memory.JoinGuestThread(a)
	case "pthread_mutex_lock", "pthread_mutex_trylock", "pthread_mutex_unlock", "pthread_mutex_destroy":
		return h.mutexOperation(name, a[0])
	case "pthread_cond_broadcast", "pthread_cond_signal", "pthread_cond_wait", "pthread_cond_destroy":
		return h.conditionOperation(name, a)
	case "__cxa_atexit":
		if a[0] == 0 {
			return 0, errors.New("original __cxa_atexit callback is null")
		}
		h.mu.Lock()
		h.callbacks = append(h.callbacks, hostExitCallback{a[0], a[1], a[2]})
		h.mu.Unlock()
		return 0, nil
	case "__cxa_finalize":
		return 0, h.finalize(a[0])
	case "__errno":
		return h.errnoAddress()
	case "getpagesize":
		return uint64(os.Getpagesize()), nil
	case "getauxval":
		if value, ok := h.auxiliary[a[0]]; ok {
			return value, nil
		}
		return 0, h.setErrno(hostENOENT)
	case "__system_property_get":
		if _, err := h.cString(a[0]); err != nil {
			return 0, err
		}
		// AOSP SystemProperties::Find returns nullptr while uninitialized;
		// SystemProperties::Get then writes only value[0] and returns zero.
		// No property area exists in this Windows process.
		return 0, h.writeMemory(a[1], []byte{0})
	case "__system_property_find":
		_, err := h.cString(a[0])
		return 0, err
	case "__system_property_read":
		return 0, errors.New("no genuine prop_info exists in the uninitialized Android property area")
	case "clock_gettime":
		result, err := h.clockTime(a[0], a[1])
		return h.libcResult(result, err)
	case "syscall":
		var arguments [8]uint64
		copy(arguments[:], a[1:])
		result, err := h.Syscall(a[0], arguments)
		return h.libcResult(result, err)
	case "socket":
		result, err := h.openSocket(a)
		return h.libcResult(result, err)
	case "bind":
		result, err := h.bindSocket(a)
		return h.libcResult(result, err)
	case "dlsym":
		return h.dynamicSymbol(a[0], a[1])
	case "dlerror":
		return h.dynamicError()
	case "exit":
		if err := h.finalize(0); err != nil {
			return 0, err
		}
		// Invoke the actual process CRT exit with its own stdio/atexit
		// semantics. The OS also tears down this process's owned resources.
		syscall.SyscallN(h.crt.exit, uintptr(uint32(a[0])))
		return 0, errors.New("actual UCRT exit unexpectedly returned")
	case "abort", "__stack_chk_fail":
		return 0, fmt.Errorf("original native code requested fatal %s; execution must stop", name)
	default:
		return 0, fmt.Errorf("unsupported original ARM64 host import %q", name)
	}
}

func (h *HostABI) errnoAddress() (uint64, error) {
	address, err := h.memory.ThreadLocal()
	if err != nil {
		return 0, err
	}
	if address == 0 || address > math.MaxUint64-0x104 {
		return 0, errors.New("invalid actual guest TLS for bionic errno")
	}
	return address + 0x100, nil
}

func (h *HostABI) setErrno(code int) error {
	address, err := h.errnoAddress()
	if err != nil {
		return err
	}
	var value [4]byte
	binary.LittleEndian.PutUint32(value[:], uint32(code))
	return h.writeMemory(address, value[:])
}

func hostNegative(code int) uint64 { return uint64(-int64(code)) }

func (h *HostABI) libcResult(result uint64, err error) (uint64, error) {
	if err != nil {
		return 0, err
	}
	if signed := int64(result); signed >= -4095 && signed < 0 {
		return math.MaxUint64, h.setErrno(int(-signed))
	}
	return result, nil
}

func (h *HostABI) convertNumber(name string, a [8]uint64) (uint64, error) {
	text, err := h.cString(a[0])
	if err != nil {
		return 0, err
	}
	base := int32(a[2])
	if name != "atoi" && base != 0 && (base < 2 || base > 36) {
		if a[1] != 0 {
			if err := h.writeUint64(a[1], a[0]); err != nil {
				return 0, err
			}
		}
		return 0, h.setErrno(hostEINVAL)
	}
	errnoAddress, err := h.errnoAddress()
	if err != nil {
		return 0, err
	}
	var original [4]byte
	if err := h.readMemory(errnoAddress, original[:]); err != nil {
		return 0, err
	}
	data := make([]byte, len(text)+1)
	copy(data, text)
	// _errno and all conversions must run on the same actual Windows thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	errnoPointer, _, _ := syscall.SyscallN(h.crt.errno)
	if errnoPointer == 0 {
		return 0, errors.New("actual UCRT _errno returned null")
	}
	nativeErrno := (*int32)(unsafe.Pointer(errnoPointer))
	previous := *nativeErrno
	*nativeErrno = 0
	defer func() { *nativeErrno = previous }()
	var result uintptr
	if name == "atoi" {
		result, _, _ = syscall.SyscallN(h.crt.atoi, uintptr(unsafe.Pointer(&data[0])))
		result = uintptr(int64(int32(result)))
	} else {
		var end uintptr
		function := h.crt.strtoll
		if name == "strtoull" {
			function = h.crt.strtoull
		}
		start := uintptr(unsafe.Pointer(&data[0]))
		result, _, _ = syscall.SyscallN(function, start, uintptr(unsafe.Pointer(&end)), uintptr(uint32(a[2])))
		if end < start || end-start > uintptr(len(text)) {
			return 0, errors.New("actual UCRT numeric end pointer exceeds its owned input")
		}
		if a[1] != 0 {
			if err := h.writeUint64(a[1], a[0]+uint64(end-start)); err != nil {
				return 0, err
			}
		}
	}
	runtime.KeepAlive(data)
	if *nativeErrno != 0 {
		code, err := hostCRTError(int(*nativeErrno))
		if err != nil {
			return 0, err
		}
		if err := h.setErrno(code); err != nil {
			return 0, err
		}
	} else if err := h.writeMemory(errnoAddress, original[:]); err != nil {
		return 0, err
	}
	return uint64(result), nil
}

// UCRT's POSIX-supplement errno numbers are not Linux's numbers. Values come
// from the actual installed UCRT errno.h, not from Windows GetLastError.
func hostCRTError(code int) (int, error) {
	if code >= 1 && code <= 34 && code != 15 && code != 26 {
		return code, nil
	}
	switch code {
	case 36:
		return 35, nil
	case 38:
		return 36, nil
	case 39:
		return 37, nil
	case 40:
		return 38, nil
	case 41:
		return 39, nil
	case 42:
		return 84, nil
	case 100:
		return 98, nil
	case 101:
		return 99, nil
	case 102:
		return 97, nil
	case 103:
		return 114, nil
	case 104:
		return 74, nil
	case 105:
		return 125, nil
	case 106:
		return 103, nil
	case 107:
		return 111, nil
	case 108:
		return 104, nil
	case 109:
		return 89, nil
	case 110:
		return 113, nil
	case 111:
		return 43, nil
	case 112:
		return 115, nil
	case 113:
		return 106, nil
	case 114:
		return 40, nil
	case 115:
		return 90, nil
	case 116:
		return 100, nil
	case 117:
		return 102, nil
	case 118:
		return 101, nil
	case 119:
		return 105, nil
	case 120:
		return 61, nil
	case 121:
		return 67, nil
	case 122:
		return 42, nil
	case 123:
		return 92, nil
	case 124:
		return 63, nil
	case 125:
		return 60, nil
	case 126:
		return 107, nil
	case 127:
		return 131, nil
	case 128:
		return 88, nil
	case 129, 130:
		return 95, nil
	case 132:
		return 75, nil
	case 133:
		return 130, nil
	case 134:
		return 71, nil
	case 135:
		return 93, nil
	case 136:
		return 91, nil
	case 137:
		return 62, nil
	case 138:
		return 110, nil
	case 139:
		return 26, nil
	case 140:
		return 11, nil
	default:
		return 0, fmt.Errorf("actual UCRT errno %d has no Linux mapping", code)
	}
}

func (h *HostABI) clockTime(clock, pointer uint64) (uint64, error) {
	var seconds, nanoseconds uint64
	switch int32(clock) {
	case 0:
		var value windows.Filetime
		windows.GetSystemTimePreciseAsFileTime(&value)
		ticks := uint64(value.HighDateTime)<<32 | uint64(value.LowDateTime)
		if ticks < 116444736000000000 {
			return 0, errors.New("actual wall clock predates Unix epoch")
		}
		ticks -= 116444736000000000
		seconds, nanoseconds = ticks/10000000, ticks%10000000*100
	case 1:
		var ticks uint64
		hostUnbiasedTime.Call(uintptr(unsafe.Pointer(&ticks)))
		seconds, nanoseconds = ticks/10000000, ticks%10000000*100
	case 7:
		if err := hostInterruptTime.Find(); err != nil {
			return 0, fmt.Errorf("actual suspend-inclusive boot clock unavailable: %w", err)
		}
		var ticks uint64
		hostInterruptTime.Call(uintptr(unsafe.Pointer(&ticks)))
		seconds, nanoseconds = ticks/10000000, ticks%10000000*100
	default:
		return 0, fmt.Errorf("unsupported actual host clock ID %d", int32(clock))
	}
	var value [16]byte
	binary.LittleEndian.PutUint64(value[:8], seconds)
	binary.LittleEndian.PutUint64(value[8:], nanoseconds)
	if err := h.writeMemory(pointer, value[:]); err != nil {
		return hostNegative(hostEFAULT), nil
	}
	return 0, nil
}

func (h *HostABI) RelocateData(name string) (uint64, error) {
	if err := h.usable(); err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if address, ok := h.hostData[name]; ok {
		return address, nil
	}
	var value uint64
	switch name {
	case "environ":
		environment := os.Environ()
		pointers := make([]byte, (len(environment)+1)*8)
		for index, entry := range environment {
			address, err := h.allocateTextLocked(entry)
			if err != nil {
				return 0, err
			}
			binary.LittleEndian.PutUint64(pointers[index*8:], address)
		}
		address, err := h.allocateLocked(uint64(len(pointers)), true)
		if err != nil {
			return 0, err
		}
		if err := h.memory.Write(address, pointers); err != nil {
			return 0, err
		}
		value = address
	case "__progname":
		executable, err := os.Executable()
		if err != nil {
			return 0, fmt.Errorf("read actual host program name: %w", err)
		}
		value, err = h.allocateTextLocked(filepath.Base(executable))
		if err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unsupported genuine host data relocation %q", name)
	}
	slot, err := h.allocateLocked(8, true)
	if err != nil {
		return 0, err
	}
	var pointer [8]byte
	binary.LittleEndian.PutUint64(pointer[:], value)
	if err := h.memory.Write(slot, pointer[:]); err != nil {
		return 0, err
	}
	h.hostData[name] = slot
	return slot, nil
}

func hostHasImport(name string) bool {
	switch name {
	case "strtoll", "strtoull", "atoi", "malloc", "calloc", "free", "realloc",
		"memset", "memcpy", "memmove", "pthread_create", "pthread_join",
		"pthread_mutex_lock", "pthread_mutex_trylock", "pthread_mutex_unlock", "pthread_mutex_destroy",
		"pthread_cond_broadcast", "pthread_cond_signal", "pthread_cond_wait", "pthread_cond_destroy",
		"__cxa_atexit", "__cxa_finalize", "__errno", "getpagesize", "getauxval",
		"__system_property_find", "__system_property_get", "clock_gettime", "syscall",
		"socket", "bind", "dlsym", "dlerror", "exit":
		return true
	default:
		return false
	}
}

func (h *HostABI) dynamicSymbol(handle, text uint64) (uint64, error) {
	// RTLD_DEFAULT is the actual original loaded guest namespace. There is no
	// fabricated dlopen handle or manufactured libart/libandroid dependency.
	if handle != 0 {
		return 0, fmt.Errorf("unknown guest dynamic-library handle %#x", handle)
	}
	name, err := h.cString(text)
	if err != nil {
		return 0, err
	}
	if address, ok := h.memory.DynamicSymbol(name); ok {
		return address, nil
	}
	if hostHasImport(name) {
		return h.memory.ImportAddress(name)
	}
	if name == "environ" || name == "__progname" {
		return h.RelocateData(name)
	}
	owner, err := h.threadOwner()
	if err != nil {
		return 0, err
	}
	h.mu.Lock()
	h.loaderErrors[owner] = fmt.Sprintf("undefined actual loaded guest symbol: %s", name)
	h.mu.Unlock()
	return 0, nil
}

func (h *HostABI) dynamicError() (uint64, error) {
	owner, err := h.threadOwner()
	if err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if previous := h.loaderBuffers[owner]; previous != 0 {
		if err := h.releaseAllocationLocked(previous, true); err != nil {
			return 0, err
		}
		delete(h.loaderBuffers, owner)
	}
	message, ok := h.loaderErrors[owner]
	if !ok {
		return 0, nil
	}
	address, err := h.allocateTextLocked(message)
	if err != nil {
		return 0, err
	}
	delete(h.loaderErrors, owner)
	h.loaderBuffers[owner] = address
	return address, nil
}

func (h *HostABI) finalize(dso uint64) error {
	for {
		h.mu.Lock()
		index := -1
		for at := len(h.callbacks) - 1; at >= 0; at-- {
			if dso == 0 || h.callbacks[at].dso == dso {
				index = at
				break
			}
		}
		if index < 0 {
			h.mu.Unlock()
			return nil
		}
		if h.execute == nil {
			h.mu.Unlock()
			return errors.New("registered original __cxa_atexit destructors require SetGuestExecutor before finalization")
		}
		callback := h.callbacks[index]
		execute := h.execute
		// Remove before invoking: recursive/concurrent finalization must never
		// run the same C++ destructor twice.
		copy(h.callbacks[index:], h.callbacks[index+1:])
		h.callbacks = h.callbacks[:len(h.callbacks)-1]
		h.mu.Unlock()
		if _, err := execute(callback.function, [8]uint64{callback.argument}); err != nil {
			return fmt.Errorf("original __cxa_atexit destructor %#x: %w", callback.function, err)
		}
	}
}

func (h *HostABI) Close() error {
	h.mu.Lock()
	if h.closed {
		err := h.closeError
		h.mu.Unlock()
		return err
	}
	if h.closing {
		h.mu.Unlock()
		return errors.New("reentrant/concurrent host ABI teardown")
	}
	h.closing = true
	h.mu.Unlock()
	// Destructors can call the ABI again, including registering another exit
	// callback. Keep actual files, allocators, synchronization and UCRT alive.
	result := h.finalize(0)
	h.mu.Lock()
	// No further guest imports may start after original destructors finish.
	// Do not hold the state lock while closing descriptors: a genuine read
	// holds its descriptor lock while copying into the guest boundary.
	h.closed = true
	h.closeError = errors.New("host ABI teardown in progress")
	resources := h.descriptors
	h.descriptors = nil
	h.mu.Unlock()
	for _, resource := range resources {
		result = errors.Join(result, resource.close())
	}
	h.mu.Lock()
	for address, mutex := range h.mutexes {
		if mutex.owner != 0 {
			result = errors.Join(result, fmt.Errorf("guest mutex %#x still owned during teardown", address))
		}
	}
	if h.winsockStarted {
		result = errors.Join(result, windows.WSACleanup())
		h.winsockStarted = false
	}
	if h.crt.library != 0 {
		result = errors.Join(result, windows.FreeLibrary(h.crt.library))
		h.crt.library = 0
	}
	for address := range h.allocations {
		if err := h.memory.Free(address); err != nil {
			result = errors.Join(result, fmt.Errorf("reclaim owned guest allocation %#x during teardown: %w", address, err))
		}
	}
	h.allocations = nil
	h.allocationOrder = nil
	h.callbacks = nil
	h.hostData = nil
	h.loaderErrors = nil
	h.loaderBuffers = nil
	h.mutexes = nil
	h.conditions = nil
	h.closed = true
	h.closing = false
	h.closeError = result
	h.mu.Unlock()
	return result
}
