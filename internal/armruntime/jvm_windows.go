//go:build windows && amd64

package armruntime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// JVMConfig names the genuine installed VM, the source-built worker.c bridge,
// and the original APK/framework class archives. No Android profile is supplied.
type JVMConfig struct {
	Library         string
	Bridge          string
	ClassPath       string
	POSIXUIDCommand string
	// PublishDDM subscribes to actual original framework monitor chunks.
	// Data is borrowed only until return; nil means no monitor subscriber.
	// This never supplies an Android JDWP or device-integrity verdict.
	PublishDDM func(kind uint32, data []byte) error
}

// JVM owns the real C-created VM thread. worker.c, not a Go-attached thread,
// performs JNI calls and owns the array factory's global reference.
type JVM struct {
	mu            sync.Mutex
	library       *syscall.DLL
	worker        uintptr
	ownerThreadID uint32
	mainQueue     uintptr
	disposeQueue  uintptr
	application   uintptr
	appBootstrap  uintptr
	closeApp      uintptr
	invoke        *syscall.Proc
	stop          *syscall.Proc
	threadStart   *syscall.Proc
	threadWait    *syscall.Proc
	threadJoin    *syscall.Proc
	setDispatcher *syscall.Proc
	exports       map[string]*syscall.Proc
	publishDDM    func(kind uint32, data []byte) error
	properties    hostPropertyStore
	active        int
	closing       bool
	closed        bool
	guest         *GuestJNI
	nextThread    uintptr
	threads       map[uintptr]*jvmGuestThread
	threadTokens  map[uintptr]*jvmGuestThread
}

type jvmGuestThread struct {
	token        uintptr
	handle       uintptr
	callback     uintptr
	argument     uintptr
	hostThreadID uint32
	complete     bool
	waiting      bool
	failure      error
}

// worker.c's native dispatcher and host ports are process-global, and HotSpot
// does not support independent simultaneous VMs in one process.
var jvmProcess struct {
	sync.Mutex
	opening bool
	owner   *JVM
}

var jvmCallbackOnce sync.Once
var jvmNativeCallback uintptr
var jvmThreadCallback uintptr
var jvmDdmCallback uintptr
var jvmPropertyCallback uintptr

func jniCString(value string) ([]byte, error) {
	if strings.IndexByte(value, 0) >= 0 {
		return nil, errors.New("JNI C string contains an embedded NUL")
	}
	text := make([]byte, len(value)+1)
	copy(text, value)
	return text, nil
}

func jniModifiedUTF8(value string) []byte {
	text := make([]byte, 0, len(value)+1)
	appendUnit := func(unit uint32) {
		switch {
		case unit == 0:
			text = append(text, 0xc0, 0x80)
		case unit < 0x80:
			text = append(text, byte(unit))
		case unit < 0x800:
			text = append(text, byte(0xc0|(unit>>6)), byte(0x80|(unit&63)))
		default:
			text = append(text, byte(0xe0|(unit>>12)), byte(0x80|((unit>>6)&63)), byte(0x80|(unit&63)))
		}
	}
	for _, character := range value {
		unit := uint32(character)
		if unit > 0xffff {
			unit -= 0x10000
			appendUnit(0xd800 + (unit >> 10))
			appendUnit(0xdc00 + (unit & 1023))
		} else {
			appendUnit(unit)
		}
	}
	return append(text, 0)
}

// jniCallShape is the fixed JNI ABI supported by the actual worker.c export.
// Raw variadic and V entries are deliberately excluded: ARM64 argument storage
// is not Windows x64 varargs. GuestJNI translates supported V entries to A.
func jniCallShape(index uint) (int, byte, bool) {
	if index >= 36 && index <= 63 && (index-36)%3 == 0 {
		return 3, "LZBCSIJFDV"[(index-36)/3], true
	}
	if index >= 66 && index <= 93 && (index-66)%3 == 0 {
		if index == 87 || index == 90 {
			return 0, 0, false // worker.c has no typed nonvirtual floating export.
		}
		return 4, "LZBCSIJFDV"[(index-66)/3], true
	}
	if index >= 116 && index <= 143 && (index-116)%3 == 0 {
		return 3, "LZBCSIJFDV"[(index-116)/3], true
	}
	if index >= 95 && index <= 103 {
		return 2, "LZBCSIJFD"[index-95], true
	}
	if index >= 104 && index <= 112 {
		return 3, 'V', true
	}
	if index >= 145 && index <= 153 {
		return 2, "LZBCSIJFD"[index-145], true
	}
	if index >= 154 && index <= 162 {
		return 3, 'V', true
	}
	if index >= 175 && index <= 182 {
		return 1, 'L', true
	}
	if index >= 183 && index <= 190 {
		return 2, 'L', true
	}
	if index >= 191 && index <= 198 {
		return 3, 'V', true
	}
	if index >= 199 && index <= 214 {
		return 4, 'V', true
	}
	switch index {
	case 4:
		return 0, 'I', true
	case 5:
		return 4, 'L', true
	case 6, 7, 8, 10, 20, 21, 25, 27, 31, 167, 226:
		return 1, 'L', true
	case 9, 12, 30, 33, 94, 113, 144, 172:
		return 3, 'L', true
	case 11, 24, 32:
		return 2, 'Z', true
	case 13, 19, 26, 164, 168, 171, 217, 218, 219, 232:
		return 1, 'I', true
	case 14:
		return 2, 'I', true
	case 15:
		return 0, 'L', true
	case 16, 17:
		return 0, 'V', true
	case 22, 23, 227:
		return 1, 'V', true
	case 163, 165, 169, 173, 222, 224, 229:
		return 2, 'L', true
	case 166, 170, 225:
		return 2, 'V', true
	case 174, 223:
		return 3, 'V', true
	case 215:
		return 3, 'I', true
	case 216:
		return 1, 'I', true
	case 220, 221:
		return 4, 'V', true
	case 228:
		return 0, 'Z', true
	case 230:
		return 1, 'L', true
	case 231:
		return 1, 'J', true
	}
	return 0, 0, false
}

func jniResult(value uintptr, kind byte) uintptr {
	switch kind {
	case 'Z':
		return uintptr(uint8(value))
	case 'B':
		return uintptr(int64(int8(value)))
	case 'C':
		return uintptr(uint16(value))
	case 'S':
		return uintptr(int64(int16(value)))
	case 'I':
		return uintptr(int64(int32(value)))
	case 'F':
		return uintptr(uint32(value))
	case 'V':
		return 0
	default:
		return value
	}
}

func OpenJVM(config JVMConfig) (*JVM, error) {
	return openJVM(config, nil)
}

func openJVM(config JVMConfig, application *HostApplicationConfig) (*JVM, error) {
	if config.Library == "" || config.Bridge == "" || config.ClassPath == "" {
		return nil, errors.New("genuine JVM library, C bridge and original classpath are required")
	}
	hasApplication := application != nil
	var scope HostApplicationConfig
	if hasApplication {
		scope = *application
		if scope.DataDirectory == "" || scope.ArchivePath == "" || scope.PackageName == "" || scope.NativeDirectory == "" {
			return nil, errors.New("Windows Application requires owned data, verified archive/package and native directory")
		}
	}
	jvmProcess.Lock()
	if jvmProcess.opening || jvmProcess.owner != nil {
		jvmProcess.Unlock()
		return nil, errors.New("the process already owns a genuine JVM worker")
	}
	jvmProcess.opening = true
	jvmProcess.Unlock()
	defer func() {
		jvmProcess.Lock()
		jvmProcess.opening = false
		jvmProcess.Unlock()
	}()

	bridgePath, err := filepath.Abs(config.Bridge)
	if err != nil {
		return nil, err
	}
	libraryPath, err := filepath.Abs(config.Library)
	if err != nil {
		return nil, err
	}
	widePath, err := syscall.UTF16PtrFromString(libraryPath)
	if err != nil {
		return nil, err
	}
	classPath := config.ClassPath
	if hasApplication {
		hostPath, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(bridgePath), "windows-host"))
		if err != nil {
			return nil, fmt.Errorf("source-built Windows Application backend beside the C bridge: %w", err)
		}
		for _, relative := range []string{filepath.Join("snapnative", "host", "WindowsApplicationBootstrap.class"), "WindowsAccumulatorBootstrap.class"} {
			bootstrap, err := os.Stat(filepath.Join(hostPath, relative))
			if err != nil {
				return nil, fmt.Errorf("source-built Windows account bootstrap %s beside the C bridge: %w", relative, err)
			}
			if !bootstrap.Mode().IsRegular() {
				return nil, fmt.Errorf("source-built Windows account bootstrap %s is not a regular classfile", relative)
			}
		}
		classPath += string(os.PathListSeparator) + hostPath
	}
	classpath, err := jniCString(classPath)
	if err != nil {
		return nil, err
	}
	cleanerPath := filepath.Join(filepath.Dir(bridgePath), "hostcompat")
	if _, err := os.Stat(filepath.Join(cleanerPath, "sun", "misc", "Cleaner.class")); err != nil {
		return nil, fmt.Errorf("source-built JVM cleanup compatibility beside the C bridge: %w", err)
	}
	cleaner, err := jniCString(cleanerPath)
	if err != nil {
		return nil, err
	}
	bridge, err := syscall.LoadDLL(bridgePath)
	if err != nil {
		return nil, fmt.Errorf("load genuine native JVM bridge: %w", err)
	}
	j := &JVM{
		library:      bridge,
		exports:      make(map[string]*syscall.Proc),
		publishDDM:   config.PublishDDM,
		threads:      make(map[uintptr]*jvmGuestThread),
		threadTokens: make(map[uintptr]*jvmGuestThread),
	}
	for _, name := range []string{
		"NativeJVMStart", "NativeJVMStatus", "NativeJVMCall", "NativeJVMStop",
		"NativeJVMGuestThreadStart", "NativeJVMGuestThreadWait", "NativeJVMGuestThreadJoin",
		"NativeSetHostPosixUID", "NativeSetHostArrayFactory", "NativeSetGuestDispatcher",
		"NativeAndroidLogIsLoggable", "NativeLinuxGetUID", "NativeNewUnpaddedArray",
		"NativeBinderAllocate", "NativeBinderFinalizer", "NativeBinderGetExtension", "NativeBinderSetExtension",
		"NativeApplyFreeFunction", "NativeRegisterAllocation", "NativeRegisterFree",
		"NativeQueueInit", "NativeQueueDestroy", "NativeQueuePollOnce", "NativeQueueWake", "NativeQueueIsPolling",
		"NativeHostUptimeMillis", "NativeHostUptimeNanos", "NativeHostElapsedRealtime", "NativeHostElapsedRealtimeNanos",
		"NativeSetDdmPublisher", "NativeDdmPublishChunk",
		"NativeSetHostPropertyDispatcher", "NativeHostPropertyString", "NativeHostPropertyInt",
		"NativeHostPropertyLong", "NativeHostPropertyBoolean", "NativeHostPropertySet",
		"NativeGuestI", "NativeGuestF", "NativeGuestC", "NativeGuestD",
	} {
		function, findErr := bridge.FindProc(name)
		if findErr != nil {
			bridge.Release()
			return nil, fmt.Errorf("required worker.c export %s: %w", name, findErr)
		}
		j.exports[name] = function
	}
	j.invoke = j.exports["NativeJVMCall"]
	j.stop = j.exports["NativeJVMStop"]
	j.threadStart = j.exports["NativeJVMGuestThreadStart"]
	j.threadWait = j.exports["NativeJVMGuestThreadWait"]
	j.threadJoin = j.exports["NativeJVMGuestThreadJoin"]
	j.setDispatcher = j.exports["NativeSetGuestDispatcher"]
	worker, _, callErr := j.exports["NativeJVMStart"].Call(uintptr(unsafe.Pointer(widePath)), uintptr(unsafe.Pointer(unsafe.SliceData(classpath))), uintptr(unsafe.Pointer(unsafe.SliceData(cleaner))))
	runtime.KeepAlive(widePath)
	runtime.KeepAlive(classpath)
	runtime.KeepAlive(cleaner)
	if worker == 0 {
		bridge.Release()
		return nil, fmt.Errorf("create genuine C-thread JVM worker: %w", callErr)
	}
	j.worker = worker
	status, _, _ := j.exports["NativeJVMStatus"].Call(worker)
	if int32(status) != 0 {
		stopped, _, stopErr := j.stop.Call(worker)
		if stopped == 0 {
			return nil, fmt.Errorf("JNI_CreateJavaVM returned %d; C worker cleanup failed: %w", int32(status), stopErr)
		}
		bridge.Release()
		return nil, fmt.Errorf("genuine JNI_CreateJavaVM returned %d", int32(status))
	}
	// The exact worker.c x64 prefix is HANDLE thread; DWORD thread_id. This
	// reads its actual owner ID; it never invents an attachment or environment.
	j.ownerThreadID = *(*uint32)(unsafe.Pointer(worker + unsafe.Sizeof(uintptr(0))))
	jvmProcess.Lock()
	jvmProcess.owner = j
	jvmProcess.Unlock()
	initializeJVMCallbacks()
	j.exports["NativeSetHostPropertyDispatcher"].Call(jvmPropertyCallback)
	if config.PublishDDM != nil {
		j.exports["NativeSetDdmPublisher"].Call(jvmDdmCallback)
	}
	if err := j.configureHostPorts(config.POSIXUIDCommand); err != nil {
		return nil, errors.Join(err, j.Close())
	}
	if hasApplication {
		if err := j.attachApplication(scope); err != nil {
			return nil, errors.Join(err, j.Close())
		}
	}
	return j, nil
}

func (j *JVM) begin() error {
	if j == nil {
		return errors.New("genuine JVM is absent")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.closing || j.worker == 0 {
		return errors.New("genuine JVM worker is closed or closing")
	}
	j.active++
	return nil
}

func (j *JVM) end() {
	j.mu.Lock()
	j.active--
	j.mu.Unlock()
}

//go:uintptrescapes
func (j *JVM) callWorker(index uint, virtualMachine bool, arguments ...uintptr) (uintptr, error) {
	var result uintptr
	var inputs [6]uintptr
	copy(inputs[:], arguments)
	vm := uintptr(0)
	if virtualMachine {
		vm = 1
	}
	ok, _, callErr := j.invoke.Call(j.worker, vm, uintptr(index), uintptr(len(arguments)), uintptr(unsafe.Pointer(&inputs[0])), uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(&inputs)
	runtime.KeepAlive(&result)
	if ok == 0 {
		return 0, fmt.Errorf("genuine C-thread JNI/VM entry %d rejected: %w", index, callErr)
	}
	if virtualMachine {
		return jniResult(result, 'I'), nil
	}
	_, kind, _ := jniCallShape(index)
	return jniResult(result, kind), nil
}

// Call accepts host pointers and fixed JNI arguments, never guest pointers or
// raw ARM64 va_list. JNI exceptions remain pending until an explicit JNI clear.
//
//go:uintptrescapes
func (j *JVM) Call(index uint, virtualMachine bool, arguments ...uintptr) (uintptr, error) {
	var count int
	if virtualMachine {
		switch index {
		case 4, 6, 7:
			count = 2
		case 5:
			count = 0
		default:
			return 0, fmt.Errorf("unsupported genuine VM entry %d; DestroyJavaVM is owned by Close", index)
		}
	} else {
		var supported bool
		count, _, supported = jniCallShape(index)
		if !supported {
			return 0, fmt.Errorf("JNI entry %d has no supported fixed/typed worker.c ABI", index)
		}
	}
	if len(arguments) != count {
		return 0, fmt.Errorf("JNI/VM entry %d requires %d arguments, got %d", index, count, len(arguments))
	}
	if err := j.begin(); err != nil {
		return 0, err
	}
	defer j.end()
	return j.callWorker(index, virtualMachine, arguments...)
}

func (j *JVM) Exception() (bool, error) {
	value, err := j.Call(228, false)
	return uint8(value) != 0, err
}

func (j *JVM) requireResult(value uintptr, operation string) error {
	pending, err := j.Exception()
	if err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("%s raised a genuine pending Java exception", operation)
	}
	if value == 0 {
		return fmt.Errorf("%s returned a genuine null JNI result", operation)
	}
	return nil
}

func (j *JVM) Class(name string) (uintptr, error) {
	text, err := jniCString(name)
	if err != nil {
		return 0, err
	}
	value, err := j.Call(6, false, uintptr(unsafe.Pointer(unsafe.SliceData(text))))
	runtime.KeepAlive(text)
	if err != nil {
		return 0, err
	}
	if err := j.requireResult(value, "FindClass("+name+")"); err != nil {
		return 0, err
	}
	return value, nil
}

func (j *JVM) Method(class uintptr, name, descriptor string, static bool) (uintptr, error) {
	methodName, err := jniCString(name)
	if err != nil {
		return 0, err
	}
	signature, err := jniCString(descriptor)
	if err != nil {
		return 0, err
	}
	index := uint(33)
	if static {
		index = 113
	}
	value, err := j.Call(index, false, class, uintptr(unsafe.Pointer(unsafe.SliceData(methodName))), uintptr(unsafe.Pointer(unsafe.SliceData(signature))))
	runtime.KeepAlive(methodName)
	runtime.KeepAlive(signature)
	if err != nil {
		return 0, err
	}
	if err := j.requireResult(value, "GetMethodID("+name+descriptor+")"); err != nil {
		return 0, err
	}
	return value, nil
}

func (j *JVM) field(class uintptr, name, descriptor string, static bool) (uintptr, error) {
	fieldName, err := jniCString(name)
	if err != nil {
		return 0, err
	}
	signature, err := jniCString(descriptor)
	if err != nil {
		return 0, err
	}
	index := uint(94)
	if static {
		index = 144
	}
	value, err := j.Call(index, false, class, uintptr(unsafe.Pointer(unsafe.SliceData(fieldName))), uintptr(unsafe.Pointer(unsafe.SliceData(signature))))
	runtime.KeepAlive(fieldName)
	runtime.KeepAlive(signature)
	if err != nil {
		return 0, err
	}
	if err := j.requireResult(value, "GetFieldID("+name+":"+descriptor+")"); err != nil {
		return 0, err
	}
	return value, nil
}

type jniNativeRecord struct {
	name       uintptr
	descriptor uintptr
	function   uintptr
}

func (j *JVM) registerHostNative(className, name, descriptor, export string) error {
	class, err := j.Class(className)
	if err != nil {
		return err
	}
	defer j.Call(23, false, class)
	methodName, err := jniCString(name)
	if err != nil {
		return err
	}
	signature, err := jniCString(descriptor)
	if err != nil {
		return err
	}
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(unsafe.SliceData(methodName))
	pin.Pin(unsafe.SliceData(signature))
	record := jniNativeRecord{
		name:       uintptr(unsafe.Pointer(unsafe.SliceData(methodName))),
		descriptor: uintptr(unsafe.Pointer(unsafe.SliceData(signature))),
		function:   j.exports[export].Addr(),
	}
	status, err := j.Call(215, false, class, uintptr(unsafe.Pointer(&record)), 1)
	runtime.KeepAlive(methodName)
	runtime.KeepAlive(signature)
	runtime.KeepAlive(&record)
	if err != nil {
		return err
	}
	pending, err := j.Exception()
	if err != nil {
		return err
	}
	if int32(status) != 0 || pending {
		return fmt.Errorf("real JNI RegisterNatives failed for %s.%s%s: status %d, exception %t", className, name, descriptor, int32(status), pending)
	}
	return nil
}

func (j *JVM) configureHostPorts(uidCommand string) error {
	if err := j.registerHostNative("android/util/Log", "isLoggable", "(Ljava/lang/String;I)Z", "NativeAndroidLogIsLoggable"); err != nil {
		return err
	}
	if uidCommand == "" {
		uidCommand = "C:/Program Files/Git/usr/bin/id.exe"
	}
	raw, err := exec.Command(uidCommand, "-u").Output()
	if err != nil {
		return fmt.Errorf("actual installed Git POSIX getuid: %w", err)
	}
	uid, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return fmt.Errorf("actual host POSIX UID: %w", err)
	}
	j.exports["NativeSetHostPosixUID"].Call(uintptr(uid))
	if err := j.registerHostNative("libcore/io/Linux", "getuid", "()I", "NativeLinuxGetUID"); err != nil {
		return err
	}
	class, err := j.Class("java/lang/reflect/Array")
	if err != nil {
		return err
	}
	defer j.Call(23, false, class)
	method, err := j.Method(class, "newInstance", "(Ljava/lang/Class;I)Ljava/lang/Object;", true)
	if err != nil {
		return err
	}
	global, err := j.Call(21, false, class)
	if err != nil {
		return err
	}
	if err := j.requireResult(global, "retain genuine VM array factory"); err != nil {
		return err
	}
	j.exports["NativeSetHostArrayFactory"].Call(global, method)
	// Ownership transferred to worker.c, which deletes it before DestroyJavaVM.
	if err := j.registerHostNative("dalvik/system/VMRuntime", "newUnpaddedArray", "(Ljava/lang/Class;I)Ljava/lang/Object;", "NativeNewUnpaddedArray"); err != nil {
		return err
	}
	// Actual local memory owners and original Java cleanup/dispatch. No Binder
	// IPC, service directory, Android identities or integrity verdicts supplied.
	for _, method := range []struct{ class, name, descriptor, export string }{
		{"android/os/Binder", "getNativeBBinderHolder", "()J", "NativeBinderAllocate"},
		{"android/os/Binder", "getNativeFinalizer", "()J", "NativeBinderFinalizer"},
		{"android/os/Binder", "getExtension", "()Landroid/os/IBinder;", "NativeBinderGetExtension"},
		{"android/os/Binder", "setExtension", "(Landroid/os/IBinder;)V", "NativeBinderSetExtension"},
		{"libcore/util/NativeAllocationRegistry", "applyFreeFunction", "(JJ)V", "NativeApplyFreeFunction"},
		{"dalvik/system/VMRuntime", "registerNativeAllocation", "(J)V", "NativeRegisterAllocation"},
		{"dalvik/system/VMRuntime", "registerNativeFree", "(J)V", "NativeRegisterFree"},
		{"android/os/MessageQueue", "nativeInit", "()J", "NativeQueueInit"},
		{"android/os/MessageQueue", "nativeDestroy", "(J)V", "NativeQueueDestroy"},
		{"android/os/MessageQueue", "nativePollOnce", "(JI)V", "NativeQueuePollOnce"},
		{"android/os/MessageQueue", "nativeWake", "(J)V", "NativeQueueWake"},
		{"android/os/MessageQueue", "nativeIsPolling", "(J)Z", "NativeQueueIsPolling"},
		{"android/os/SystemClock", "uptimeMillis", "()J", "NativeHostUptimeMillis"},
		{"android/os/SystemClock", "uptimeNanos", "()J", "NativeHostUptimeNanos"},
		{"android/os/SystemClock", "elapsedRealtime", "()J", "NativeHostElapsedRealtime"},
		{"android/os/SystemClock", "elapsedRealtimeNanos", "()J", "NativeHostElapsedRealtimeNanos"},
		{"org/apache/harmony/dalvik/ddmc/DdmServer", "nativeSendChunk", "(I[BII)V", "NativeDdmPublishChunk"},
		{"android/os/SystemProperties", "native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", "NativeHostPropertyString"},
		{"android/os/SystemProperties", "native_get_int", "(Ljava/lang/String;I)I", "NativeHostPropertyInt"},
		{"android/os/SystemProperties", "native_get_long", "(Ljava/lang/String;J)J", "NativeHostPropertyLong"},
		{"android/os/SystemProperties", "native_get_boolean", "(Ljava/lang/String;Z)Z", "NativeHostPropertyBoolean"},
		{"android/os/SystemProperties", "native_set", "(Ljava/lang/String;Ljava/lang/String;)V", "NativeHostPropertySet"},
	} {
		if err := j.registerHostNative(method.class, method.name, method.descriptor, method.export); err != nil {
			return err
		}
	}
	return j.prepareMainLooper()
}

// Original Java preparation on the C/JVM owner thread, backed by real Windows
// waits and clocks. No Android IPC, service graph or running Looper.loop implied.
func (j *JVM) prepareMainLooper() error {
	looper, err := j.Class("android/os/Looper")
	if err != nil {
		return err
	}
	defer j.Call(23, false, looper)
	queueClass, err := j.Class("android/os/MessageQueue")
	if err != nil {
		return err
	}
	defer j.Call(23, false, queueClass)
	prepare, err := j.Method(looper, "prepareMainLooper", "()V", true)
	if err != nil {
		return err
	}
	myQueue, err := j.Method(looper, "myQueue", "()Landroid/os/MessageQueue;", true)
	if err != nil {
		return err
	}
	dispose, err := j.Method(queueClass, "dispose", "()V", false)
	if err != nil {
		return err
	}
	if _, err := j.Call(143, false, looper, prepare, 0); err != nil {
		return err
	}
	pending, err := j.Exception()
	if err != nil {
		return err
	}
	if pending {
		return errors.New("original Looper.prepareMainLooper raised a genuine pending Java exception")
	}
	queue, err := j.Call(116, false, looper, myQueue, 0)
	if err != nil {
		return err
	}
	if err := j.requireResult(queue, "original Looper.myQueue"); err != nil {
		return err
	}
	defer j.Call(23, false, queue)
	global, err := j.Call(21, false, queue)
	if err != nil {
		return err
	}
	if err := j.requireResult(global, "retain original main MessageQueue"); err != nil {
		if global != 0 {
			j.Call(22, false, global)
		}
		return err
	}
	j.mainQueue, j.disposeQueue = global, dispose
	return nil
}

// Close exclusively owns the worker here. The original Java dispose method
// releases native resources and clears its own pointer, preventing double free
// by the original finalizer. Any previously pending throwable is restored.
func (j *JVM) disposeMainQueue() (failure error) {
	if j.mainQueue == 0 {
		return nil
	}
	saved, err := j.callWorker(15, false)
	if err != nil {
		return err
	}
	if saved != 0 {
		if _, err := j.callWorker(17, false); err != nil {
			j.callWorker(23, false, saved)
			return err
		}
		defer func() {
			pending, err := j.callWorker(228, false)
			failure = errors.Join(failure, err)
			if uint8(pending) != 0 {
				_, err = j.callWorker(17, false)
				failure = errors.Join(failure, err)
			}
			status, err := j.callWorker(13, false, saved)
			failure = errors.Join(failure, err)
			if int32(status) != 0 {
				failure = errors.Join(failure, errors.New("restore genuine pending throwable after queue disposal failed"))
			}
			_, err = j.callWorker(23, false, saved)
			failure = errors.Join(failure, err)
		}()
	}
	_, failure = j.callWorker(63, false, j.mainQueue, j.disposeQueue, 0)
	pending, err := j.callWorker(228, false)
	failure = errors.Join(failure, err)
	if uint8(pending) != 0 {
		failure = errors.Join(failure, errors.New("original MessageQueue.dispose raised a genuine pending Java exception"))
	}
	_, err = j.callWorker(22, false, j.mainQueue)
	failure = errors.Join(failure, err)
	j.mainQueue, j.disposeQueue = 0, 0
	return failure
}

// InitializeAccumulator follows the original BaseApplication q7e.b.b install.
// An actual account's Aeh owns an original EEd token reader on real scoped files;
// account-free native-smoke has no deferred file provider. This supplies no
// Android installation/service properties or trusted Google/hardware proof.
func (j *JVM) InitializeAccumulator() error {
	accumulator, err := j.newAccumulator()
	if err != nil {
		return err
	}
	if err := j.requireResult(accumulator, "original Aeh scoped constructor"); err != nil {
		return err
	}
	defer j.Call(23, false, accumulator)
	holderClass, err := j.Class("q7e")
	if err != nil {
		return err
	}
	defer j.Call(23, false, holderClass)
	holderField, err := j.field(holderClass, "b", "Lqsd;", true)
	if err != nil {
		return err
	}
	holder, err := j.Call(145, false, holderClass, holderField)
	if err != nil {
		return err
	}
	if err := j.requireResult(holder, "original q7e.b holder"); err != nil {
		return err
	}
	defer j.Call(23, false, holder)
	objectClass, err := j.Call(31, false, holder)
	if err != nil {
		return err
	}
	if err := j.requireResult(objectClass, "original qsd object class"); err != nil {
		return err
	}
	defer j.Call(23, false, objectClass)
	valueField, err := j.field(objectClass, "b", "Ljava/lang/Object;", false)
	if err != nil {
		return err
	}
	if _, err := j.Call(104, false, holder, valueField, accumulator); err != nil {
		return err
	}
	pending, err := j.Exception()
	if err != nil {
		return err
	}
	if pending {
		return errors.New("original Aeh/q7e installation raised a genuine pending Java exception")
	}
	return nil
}

func currentJVM() *JVM {
	jvmProcess.Lock()
	defer jvmProcess.Unlock()
	return jvmProcess.owner
}

func initializeJVMCallbacks() {
	jvmCallbackOnce.Do(func() {
		jvmNativeCallback = syscall.NewCallback(func(environment, class, identifier, first, second uintptr) (result uintptr) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			j := currentJVM()
			if j == nil {
				throwNativeJavaException(environment, errors.New("genuine JVM owner is unavailable"))
				return 0
			}
			j.mu.Lock()
			guest := j.guest
			j.mu.Unlock()
			if guest == nil {
				throwNativeJavaException(environment, errors.New("original ARM64 native dispatcher is unavailable"))
				return 0
			}
			return guest.dispatch(environment, class, uint(uint32(identifier)), first, second)
		})
		jvmThreadCallback = syscall.NewCallback(func(token uintptr) (result uintptr) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			j := currentJVM()
			if j == nil {
				return 0
			}
			j.mu.Lock()
			thread := j.threadTokens[token]
			if thread != nil {
				thread.hostThreadID = windows.GetCurrentThreadId()
			}
			j.mu.Unlock()
			if thread == nil {
				return 0
			}
			defer func() {
				failure := recover()
				j.mu.Lock()
				if failure != nil {
					thread.failure = fmt.Errorf("genuine C guest-thread callback panicked: %v", failure)
					result = 0
				}
				thread.complete = true
				j.mu.Unlock()
			}()
			// The original supplied callback executes on this same actual C
			// OS thread. The wrapper's lock also covers all nested JNI calls.
			result, _, _ = syscall.SyscallN(thread.callback, thread.argument)
			runtime.KeepAlive(thread)
			return result
		})
		jvmDdmCallback = syscall.NewCallback(func(environment, kind, address, length uintptr) (result uintptr) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer func() {
				if failure := recover(); failure != nil {
					throwNativeJavaException(environment, fmt.Errorf("owned DDM observer panicked: %v", failure))
					result = 0
				}
			}()
			j := currentJVM()
			if j == nil || j.publishDDM == nil {
				throwNativeJavaException(environment, errors.New("genuine DDM subscriber is unavailable"))
				return 0
			}
			var data []byte
			if length != 0 {
				if address == 0 || length > uintptr(^uint32(0)>>1) {
					throwNativeJavaException(environment, errors.New("invalid actual DDM payload range"))
					return 0
				}
				data = unsafe.Slice((*byte)(unsafe.Pointer(address)), int(length))
			}
			if err := j.publishDDM(uint32(kind), data); err != nil {
				throwNativeJavaException(environment, err)
				return 0
			}
			return 1
		})
		jvmPropertyCallback = syscall.NewCallback(func(environment, operation, address, length, other, otherLength uintptr) (result uintptr) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer func() {
				if failure := recover(); failure != nil {
					throwNativeJavaException(environment, fmt.Errorf("actual host property callback panicked: %v", failure))
					result = 0
				}
			}()
			j := currentJVM()
			if j == nil {
				throwNativeJavaException(environment, errors.New("genuine host property owner is unavailable"))
				return 0
			}
			return j.propertyDispatch(environment, operation, address, length, other, otherLength)
		})
	})
}

func (j *JVM) isNativeThread(id uint32) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if id == j.ownerThreadID {
		return true
	}
	for _, thread := range j.threadTokens {
		if !thread.complete && thread.hostThreadID == id {
			return true
		}
	}
	return false
}

func (j *JVM) bindGuest(guest *GuestJNI) error {
	initializeJVMCallbacks()
	if err := j.begin(); err != nil {
		return err
	}
	defer j.end()
	j.mu.Lock()
	if j.guest != nil && j.guest != guest {
		j.mu.Unlock()
		return errors.New("genuine JVM already has a different ARM64 JNI owner")
	}
	j.guest = guest
	j.mu.Unlock()
	j.setDispatcher.Call(jvmNativeCallback)
	return nil
}

//go:uintptrescapes
func (j *JVM) StartGuestThread(callback, argument uintptr) (uintptr, error) {
	if callback == 0 {
		return 0, errors.New("genuine C guest thread requires an actual callback")
	}
	initializeJVMCallbacks()
	if err := j.begin(); err != nil {
		return 0, err
	}
	defer j.end()
	j.mu.Lock()
	j.nextThread++
	if j.nextThread == 0 {
		j.mu.Unlock()
		return 0, errors.New("guest-thread callback token space exhausted")
	}
	thread := &jvmGuestThread{token: j.nextThread, callback: callback, argument: argument}
	j.threadTokens[thread.token] = thread
	j.mu.Unlock()
	handle, _, callErr := j.threadStart.Call(j.worker, jvmThreadCallback, thread.token)
	j.mu.Lock()
	if handle == 0 {
		delete(j.threadTokens, thread.token)
	} else {
		thread.handle = handle
		j.threads[handle] = thread
	}
	j.mu.Unlock()
	if handle == 0 {
		return 0, fmt.Errorf("create actual C guest pthread: %w", callErr)
	}
	return handle, nil
}

func (j *JVM) finishGuestThread(handle uintptr, consume bool) (uintptr, error) {
	if err := j.begin(); err != nil {
		return 0, err
	}
	defer j.end()
	j.mu.Lock()
	thread := j.threads[handle]
	if thread == nil || thread.waiting {
		j.mu.Unlock()
		return 0, errors.New("guest thread is not owned, already joined, or concurrently being waited")
	}
	thread.waiting = true
	j.mu.Unlock()
	var result uintptr
	function := j.threadWait
	if consume {
		function = j.threadJoin
	}
	ok, _, callErr := function.Call(handle, uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(&result)
	j.mu.Lock()
	thread.waiting = false
	failure := thread.failure
	if ok != 0 && consume {
		delete(j.threads, handle)
		delete(j.threadTokens, thread.token)
	}
	j.mu.Unlock()
	if ok == 0 {
		return 0, fmt.Errorf("wait/join actual C guest pthread: %w", callErr)
	}
	return result, failure
}

func (j *JVM) WaitGuestThread(thread uintptr) (uintptr, error) {
	return j.finishGuestThread(thread, false)
}

func (j *JVM) JoinGuestThread(thread uintptr) (uintptr, error) {
	return j.finishGuestThread(thread, true)
}

func (j *JVM) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return nil
	}
	if j.closing || j.active != 0 {
		j.mu.Unlock()
		return errors.New("cannot close genuine JVM during an active JNI call or thread operation")
	}
	for _, thread := range j.threads {
		if !thread.complete || thread.waiting {
			j.mu.Unlock()
			return errors.New("cannot close genuine JVM while a C guest thread is running")
		}
	}
	j.closing = true
	guest := j.guest
	threads := make([]*jvmGuestThread, 0, len(j.threads))
	for _, thread := range j.threads {
		threads = append(threads, thread)
	}
	j.mu.Unlock()
	var cleanupErr error
	for _, thread := range threads {
		var result uintptr
		ok, _, callErr := j.threadJoin.Call(thread.handle, uintptr(unsafe.Pointer(&result)))
		runtime.KeepAlive(&result)
		if ok == 0 {
			j.mu.Lock()
			j.closing = false
			j.mu.Unlock()
			return errors.Join(cleanupErr, fmt.Errorf("close actual guest thread: %w", callErr))
		}
		j.mu.Lock()
		delete(j.threads, thread.handle)
		delete(j.threadTokens, thread.token)
		j.mu.Unlock()
		cleanupErr = errors.Join(cleanupErr, thread.failure)
	}
	if guest != nil {
		cleanupErr = errors.Join(cleanupErr, guest.closeHostBuffers())
	}
	cleanupErr = errors.Join(cleanupErr, j.disposeApplication())
	cleanupErr = errors.Join(cleanupErr, j.disposeMainQueue())
	ok, _, callErr := j.stop.Call(j.worker)
	if ok == 0 {
		j.mu.Lock()
		j.closing = false
		j.mu.Unlock()
		return errors.Join(cleanupErr, fmt.Errorf("stop genuine C-thread JVM: %w", callErr))
	}
	j.exports["NativeSetDdmPublisher"].Call(0)
	j.exports["NativeSetHostPropertyDispatcher"].Call(0)
	j.setDispatcher.Call(0)
	j.mu.Lock()
	j.closed = true
	j.closing = false
	j.worker = 0
	j.mu.Unlock()
	jvmProcess.Lock()
	if jvmProcess.owner == j {
		jvmProcess.owner = nil
	}
	jvmProcess.Unlock()
	return errors.Join(cleanupErr, j.library.Release())
}

// throwNativeJavaException operates on the actual callback's JNIEnv on its
// pinned native OS thread. It also handles unsupported Java-created callback
// threads without accidentally dispatching through the owner's other JNIEnv.
// An existing genuine exception is preserved, never cleared or replaced.
func throwNativeJavaException(environment uintptr, failure error) {
	if environment == 0 || failure == nil {
		return
	}
	table := *(*uintptr)(unsafe.Pointer(environment))
	entry := func(index uint) uintptr {
		return *(*uintptr)(unsafe.Pointer(table + uintptr(index)*unsafe.Sizeof(uintptr(0))))
	}
	pending, _, _ := syscall.SyscallN(entry(228), environment)
	if uint8(pending) != 0 {
		return
	}
	name, _ := jniCString("java/lang/IllegalStateException")
	class, _, _ := syscall.SyscallN(entry(6), environment, uintptr(unsafe.Pointer(unsafe.SliceData(name))))
	runtime.KeepAlive(name)
	if class == 0 {
		return // The VM's real FindClass/OOM exception remains pending.
	}
	message := jniModifiedUTF8(failure.Error())
	syscall.SyscallN(entry(14), environment, class, uintptr(unsafe.Pointer(unsafe.SliceData(message))))
	runtime.KeepAlive(message)
	syscall.SyscallN(entry(23), environment, class)
}
