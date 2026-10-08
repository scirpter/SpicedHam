//go:build windows && amd64

package armruntime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GuestJNI carries actual HotSpot references and IDs through the ARM64 address
// space. Only memory buffers and JNI/JavaVM tables are cross-CPU translations;
// no Java objects, properties, methods, exceptions or native results are faked.
type GuestJNI struct {
	mu              sync.Mutex
	jvm             *JVM
	memory          GuestMemory
	execute         func(address uint64, arguments [8]uint64) (uint64, error)
	methods         map[uintptr]guestJNIMethod
	fields          map[uintptr]guestJNIField
	natives         map[uint]uint64
	buffers         map[uint64]guestJNIBuffer
	registeredClass uintptr
	failure         error
}

type guestJNIMethod struct {
	name       string
	descriptor string
	parameters []byte
	result     byte
	static     bool
}

type guestJNIField struct {
	descriptor string
	kind       byte
	static     bool
}

type guestJNIBuffer struct {
	release  uint
	object   uintptr // Genuine global reference keeps the backing Java object alive.
	pointer  uintptr // Actual JVM-owned Get*Chars/Get*ArrayElements allocation.
	length   uint64  // Bytes, including the MUTF-8 terminator when applicable.
	writable bool
}

func NewGuestJNI(jvm *JVM, memory GuestMemory, execute func(address uint64, arguments [8]uint64) (uint64, error)) *GuestJNI {
	j := &GuestJNI{
		jvm:     jvm,
		memory:  memory,
		execute: execute,
		methods: make(map[uintptr]guestJNIMethod),
		fields:  make(map[uintptr]guestJNIField),
		natives: make(map[uint]uint64),
		buffers: make(map[uint64]guestJNIBuffer),
	}
	if jvm == nil || memory == nil || execute == nil {
		j.failure = errors.New("genuine JVM, guest memory and original ARM64 executor are required")
	}
	return j
}

func (j *GuestJNI) NativeMethods() map[uint]uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	methods := make(map[uint]uint64, len(j.natives))
	for identifier, address := range j.natives {
		methods[identifier] = address
	}
	return methods
}

func (j *GuestJNI) Failure() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.failure
}

func (j *GuestJNI) recordFailure(err error) {
	if err == nil {
		return
	}
	j.mu.Lock()
	if j.failure == nil {
		j.failure = err
	}
	j.mu.Unlock()
}

func (j *GuestJNI) dispatch(environment, class uintptr, identifier uint, first, second uintptr) (result uintptr) {
	defer func() {
		if failure := recover(); failure != nil {
			err := fmt.Errorf("original ARM64 native callback panicked: %v", failure)
			j.recordFailure(err)
			throwNativeJavaException(environment, err)
			result = 0
		}
	}()
	var failure error
	if environment == 0 || class == 0 {
		failure = errors.New("original native callback received a null actual JNIEnv/class")
	} else if !j.jvm.isNativeThread(windows.GetCurrentThreadId()) {
		failure = errors.New("JNI callback arrived on a thread not owned by the actual C JVM/guest-thread bridge")
	}
	j.mu.Lock()
	address, found := j.natives[identifier]
	j.mu.Unlock()
	if failure == nil && (!found || address == 0) {
		failure = fmt.Errorf("original ARM64 native registration %d is unavailable", identifier)
	}
	if failure == nil {
		// NativeGuestI/F/C/D are typed genuine JNI exports. jobject values are
		// the actual callback references, not addresses of invented objects.
		arguments := [8]uint64{GuestEnvironment, uint64(class), uint64(first), uint64(second)}
		var value uint64
		value, failure = j.execute(address, arguments)
		if failure == nil {
			return uintptr(value)
		}
		failure = fmt.Errorf("original ARM64 native %d at %#x: %w", identifier, address, failure)
	}
	j.recordFailure(failure)
	throwNativeJavaException(environment, failure)
	return 0 // JNI discards this value because the actual Java exception is pending.
}

func parseJNIType(descriptor string, offset *int, allowVoid bool) (byte, error) {
	if *offset >= len(descriptor) {
		return 0, errors.New("truncated JNI descriptor")
	}
	array := false
	for *offset < len(descriptor) && descriptor[*offset] == '[' {
		array = true
		*offset++
	}
	if *offset >= len(descriptor) {
		return 0, errors.New("truncated JNI array descriptor")
	}
	kind := descriptor[*offset]
	*offset++
	switch kind {
	case 'L':
		start := *offset
		for *offset < len(descriptor) && descriptor[*offset] != ';' {
			*offset++
		}
		if *offset == start || *offset >= len(descriptor) {
			return 0, errors.New("invalid JNI reference descriptor")
		}
		*offset++
	case 'Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D':
	case 'V':
		if !allowVoid || array {
			return 0, errors.New("void is not a JNI parameter/field/array type")
		}
	default:
		return 0, fmt.Errorf("unsupported JNI descriptor type %q", kind)
	}
	if array {
		return 'L', nil
	}
	return kind, nil
}

func parseJNIMethod(name, descriptor string, static bool) (guestJNIMethod, error) {
	method := guestJNIMethod{name: name, descriptor: descriptor, static: static}
	if len(descriptor) < 3 || descriptor[0] != '(' {
		return method, errors.New("invalid JNI method descriptor")
	}
	offset := 1
	for offset < len(descriptor) && descriptor[offset] != ')' {
		kind, err := parseJNIType(descriptor, &offset, false)
		if err != nil {
			return method, err
		}
		method.parameters = append(method.parameters, kind)
	}
	if offset >= len(descriptor) || descriptor[offset] != ')' {
		return method, errors.New("unterminated JNI method descriptor")
	}
	offset++
	kind, err := parseJNIType(descriptor, &offset, true)
	if err != nil {
		return method, err
	}
	if offset != len(descriptor) {
		return method, errors.New("trailing bytes in JNI method descriptor")
	}
	method.result = kind
	return method, nil
}

func (j *GuestJNI) call(index uint, arguments ...uint64) (uint64, error) {
	var inputs [6]uintptr
	if len(arguments) > len(inputs) {
		return 0, errors.New("guest JNI arguments exceed the real fixed C ABI")
	}
	for offset, value := range arguments {
		inputs[offset] = uintptr(value)
	}
	result, err := j.jvm.Call(index, false, inputs[:len(arguments)]...)
	return uint64(result), err
}

func (j *GuestJNI) writePointer(address uint64, pointer uint64) error {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], pointer)
	return j.memory.Write(address, data[:])
}

func (j *GuestJNI) lookup(index uint, a [8]uint64) (uint64, error) {
	name, err := j.memory.String(a[2])
	if err != nil {
		return 0, err
	}
	descriptor, err := j.memory.String(a[3])
	if err != nil {
		return 0, err
	}
	nameText, err := jniCString(name)
	if err != nil {
		return 0, err
	}
	descriptorText, err := jniCString(descriptor)
	if err != nil {
		return 0, err
	}
	value, err := j.jvm.Call(index, false, uintptr(a[1]), uintptr(unsafe.Pointer(unsafe.SliceData(nameText))), uintptr(unsafe.Pointer(unsafe.SliceData(descriptorText))))
	runtime.KeepAlive(nameText)
	runtime.KeepAlive(descriptorText)
	if err != nil || value == 0 {
		return uint64(value), err
	}
	pending, err := j.jvm.Exception()
	if err != nil || pending {
		return uint64(value), err
	}
	if index == 33 || index == 113 {
		method, err := parseJNIMethod(name, descriptor, index == 113)
		if err != nil {
			return 0, err
		}
		j.mu.Lock()
		j.methods[value] = method
		j.mu.Unlock()
	} else {
		offset := 0
		kind, err := parseJNIType(descriptor, &offset, false)
		if err != nil {
			return 0, err
		}
		if offset != len(descriptor) {
			return 0, errors.New("trailing bytes in genuine JNI field descriptor")
		}
		j.mu.Lock()
		j.fields[value] = guestJNIField{descriptor: descriptor, kind: kind, static: index == 144}
		j.mu.Unlock()
	}
	return uint64(value), nil
}

func (j *GuestJNI) fieldType(identifier uintptr, kind byte, static bool) error {
	j.mu.Lock()
	field, found := j.fields[identifier]
	j.mu.Unlock()
	if !found {
		return errors.New("guest JNI field operation has no genuinely resolved descriptor")
	}
	if field.kind != kind || field.static != static {
		return fmt.Errorf("JNI field operation mismatches original descriptor %s/static=%t", field.descriptor, field.static)
	}
	return nil
}

// ARM64 va_list has __stack, __gr_top, __vr_top, __gr_offs, __vr_offs. Java
// primitives and references occupy one slot; C varargs promote float to double.
// The actual x64 JVM receives jvalue[] A storage, never this ARM64 structure.
func (j *GuestJNI) valuesV(address uint64, types []byte, values []uint64) error {
	var data [32]byte
	if err := j.memory.Read(address, data[:]); err != nil {
		return err
	}
	stack := binary.LittleEndian.Uint64(data[0:8])
	generalTop := binary.LittleEndian.Uint64(data[8:16])
	vectorTop := binary.LittleEndian.Uint64(data[16:24])
	generalOffset := int64(int32(binary.LittleEndian.Uint32(data[24:28])))
	vectorOffset := int64(int32(binary.LittleEndian.Uint32(data[28:32])))
	if generalOffset < -64 || (generalOffset < 0 && generalOffset%8 != 0) || vectorOffset < -128 || (vectorOffset < 0 && vectorOffset%16 != 0) {
		return errors.New("invalid original ARM64 va_list register-save offsets")
	}
	for offset, kind := range types {
		var pointer uint64
		floating := kind == 'F' || kind == 'D'
		switch {
		case floating && vectorOffset < 0:
			if uint64(-vectorOffset) > vectorTop {
				return errors.New("ARM64 va_list vector address underflows")
			}
			pointer = vectorTop - uint64(-vectorOffset)
			vectorOffset += 16
		case !floating && generalOffset < 0:
			if uint64(-generalOffset) > generalTop {
				return errors.New("ARM64 va_list general address underflows")
			}
			pointer = generalTop - uint64(-generalOffset)
			generalOffset += 8
		default:
			if stack > math.MaxUint64-15 {
				return errors.New("ARM64 va_list stack address overflows")
			}
			pointer = (stack + 7) &^ uint64(7)
			stack = pointer + 8
		}
		var slot [8]byte
		if err := j.memory.Read(pointer, slot[:]); err != nil {
			return err
		}
		raw := binary.LittleEndian.Uint64(slot[:])
		if kind == 'F' {
			raw = uint64(math.Float32bits(float32(math.Float64frombits(raw))))
		}
		values[offset] = jniArgumentBits(raw, kind)
	}
	return nil
}

func jniArgumentBits(value uint64, kind byte) uint64 {
	switch kind {
	case 'Z', 'B':
		return uint64(uint8(value))
	case 'C', 'S':
		return uint64(uint16(value))
	case 'I', 'F':
		return uint64(uint32(value))
	default:
		return value
	}
}

func (j *GuestJNI) valuesA(address uint64, types []byte, values []uint64) error {
	if len(types) != 0 && address == 0 {
		return errors.New("original JNI A call has a null nonempty jvalue array")
	}
	for offset, kind := range types {
		if uint64(offset) > (math.MaxUint64-address)/8 {
			return errors.New("guest JNI jvalue address overflows")
		}
		var slot [8]byte
		if err := j.memory.Read(address+uint64(offset)*8, slot[:]); err != nil {
			return err
		}
		values[offset] = jniArgumentBits(binary.LittleEndian.Uint64(slot[:]), kind)
	}
	return nil
}

func (j *GuestJNI) invokeMethod(index uint, a [8]uint64) (uint64, error) {
	var base uint
	var static, nonvirtual, constructor bool
	switch {
	case index >= 28 && index <= 30:
		base, constructor = 28, true
	case index >= 34 && index <= 63:
		base = 34
	case index >= 64 && index <= 93:
		base, nonvirtual = 64, true
	case index >= 114 && index <= 143:
		base, static = 114, true
	default:
		return 0, fmt.Errorf("unsupported guest JNI method entry %d", index)
	}
	form := (index - base) % 3
	if form == 0 {
		return 0, fmt.Errorf("raw ARM64 variadic JNI entry %d requires unavailable input FP/stack registers; use actual V/A ABI", index)
	}
	hostIndex := index
	if form == 1 {
		hostIndex++
	}
	_, resultKind, supported := jniCallShape(hostIndex)
	if !supported {
		return 0, fmt.Errorf("JNI entry %d lacks a typed worker.c export", hostIndex)
	}
	methodArgument, valuesArgument := 2, 3
	if nonvirtual {
		methodArgument, valuesArgument = 3, 4
	}
	j.mu.Lock()
	method, found := j.methods[uintptr(a[methodArgument])]
	j.mu.Unlock()
	if !found {
		return 0, errors.New("original JNI method invocation has no genuinely resolved descriptor")
	}
	if method.static != static || (constructor && (method.name != "<init>" || method.result != 'V')) || (!constructor && method.result != resultKind) {
		return 0, fmt.Errorf("JNI entry %d mismatches original method %s%s/static=%t", index, method.name, method.descriptor, method.static)
	}
	values := make([]uint64, len(method.parameters))
	var err error
	if form == 1 {
		// A zero-parameter V call need not dereference otherwise unused va_list.
		if len(values) != 0 {
			err = j.valuesV(a[valuesArgument], method.parameters, values)
		}
	} else {
		err = j.valuesA(a[valuesArgument], method.parameters, values)
	}
	if err != nil {
		return 0, err
	}
	var pin runtime.Pinner
	defer pin.Unpin()
	pointer := uintptr(0)
	if len(values) != 0 {
		pin.Pin(&values[0])
		pointer = uintptr(unsafe.Pointer(&values[0]))
	}
	var result uintptr
	if nonvirtual {
		result, err = j.jvm.Call(hostIndex, false, uintptr(a[1]), uintptr(a[2]), uintptr(a[3]), pointer)
	} else {
		result, err = j.jvm.Call(hostIndex, false, uintptr(a[1]), uintptr(a[2]), pointer)
	}
	runtime.KeepAlive(values)
	if err != nil {
		return 0, err
	}
	if resultKind == 'F' || resultKind == 'D' {
		if err := j.memory.SetFloatResult(uint64(result), resultKind == 'D'); err != nil {
			return 0, err
		}
		return a[0], nil // The ARM64 return is S0/D0, not an invented X0 pointer.
	}
	return uint64(result), nil
}

var originalJNINatives = [...]struct {
	name       string
	descriptor string
	export     string
}{
	{"i", "(Ljava/lang/String;Ljava/lang/String;)[B", "NativeGuestI"},
	{"f", "([B)[B", "NativeGuestF"},
	{"c", "([BLjava/lang/String;)[B", "NativeGuestC"},
	{"d", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", "NativeGuestD"},
}

func (j *GuestJNI) registerOriginalNatives(class uintptr, address uint64, count int32) (uint64, error) {
	if count < 0 || count > int32(len(originalJNINatives)) {
		return 0, fmt.Errorf("unsupported original JNI native registration count %d", count)
	}
	var records [4]jniNativeRecord
	var texts [4][2][]byte
	var identifiers [4]uint
	var entries [4]uint64
	var seen [4]bool
	var pin runtime.Pinner
	defer pin.Unpin()
	if count != 0 {
		pin.Pin(&records[0])
	}
	for offset := range int(count) {
		if uint64(offset) > (math.MaxUint64-address)/24 {
			return 0, errors.New("original JNI native-record address overflows")
		}
		var record [24]byte
		if err := j.memory.Read(address+uint64(offset)*24, record[:]); err != nil {
			return 0, err
		}
		name, err := j.memory.String(binary.LittleEndian.Uint64(record[0:8]))
		if err != nil {
			return 0, err
		}
		descriptor, err := j.memory.String(binary.LittleEndian.Uint64(record[8:16]))
		if err != nil {
			return 0, err
		}
		entry := binary.LittleEndian.Uint64(record[16:24])
		identifier := -1
		for candidate, expected := range originalJNINatives {
			if name == expected.name && descriptor == expected.descriptor {
				identifier = candidate
				break
			}
		}
		if identifier < 0 || entry == 0 {
			return 0, fmt.Errorf("unsupported original native registration %s%s at %#x", name, descriptor, entry)
		}
		if seen[uint(identifier)] {
			return 0, errors.New("duplicate original JNI native registration")
		}
		seen[uint(identifier)] = true
		identifiers[offset], entries[offset] = uint(identifier), entry
		texts[offset][0], err = jniCString(name)
		if err != nil {
			return 0, err
		}
		texts[offset][1], err = jniCString(descriptor)
		if err != nil {
			return 0, err
		}
		pin.Pin(unsafe.SliceData(texts[offset][0]))
		pin.Pin(unsafe.SliceData(texts[offset][1]))
		records[offset] = jniNativeRecord{
			name:       uintptr(unsafe.Pointer(unsafe.SliceData(texts[offset][0]))),
			descriptor: uintptr(unsafe.Pointer(unsafe.SliceData(texts[offset][1]))),
			function:   j.jvm.exports[originalJNINatives[identifier].export].Addr(),
		}
	}
	if err := j.jvm.bindGuest(j); err != nil {
		return 0, err
	}
	j.mu.Lock()
	retained := j.registeredClass
	j.mu.Unlock()
	fresh := false
	if count != 0 {
		if retained == 0 {
			var err error
			retained, err = j.jvm.Call(21, false, class)
			if err != nil {
				return 0, err
			}
			if err := j.jvm.requireResult(retained, "retain original registered native class"); err != nil {
				return 0, err
			}
			fresh = true
		} else {
			same, err := j.jvm.Call(24, false, retained, class)
			if err != nil {
				return 0, err
			}
			if same == 0 {
				return 0, errors.New("original typed native dispatcher cannot register an unrelated Java class")
			}
		}
	}
	pointer := uintptr(0)
	if count != 0 {
		pointer = uintptr(unsafe.Pointer(&records[0]))
	}
	status, err := j.jvm.Call(215, false, class, pointer, uintptr(count))
	runtime.KeepAlive(&records)
	runtime.KeepAlive(&texts)
	if err != nil {
		if fresh {
			j.jvm.Call(22, false, retained)
		}
		return 0, err
	}
	pending, err := j.jvm.Exception()
	if err != nil || int32(status) != 0 || pending {
		if fresh {
			j.jvm.Call(22, false, retained)
		}
		return uint64(status), err
	}
	j.mu.Lock()
	if count != 0 {
		j.registeredClass = retained
	}
	for offset := range int(count) {
		j.natives[identifiers[offset]] = entries[offset]
	}
	j.mu.Unlock()
	return uint64(status), nil
}

func (j *GuestJNI) unregisterOriginalNatives(class uintptr) (uint64, error) {
	j.mu.Lock()
	retained := j.registeredClass
	j.mu.Unlock()
	if retained == 0 {
		return 0, errors.New("original registered JNI class is unavailable")
	}
	same, err := j.jvm.Call(24, false, retained, class)
	if err != nil {
		return 0, err
	}
	if same == 0 {
		return 0, errors.New("cannot unregister an unrelated Java class through the original native bridge")
	}
	status, err := j.jvm.Call(216, false, class)
	if err != nil {
		return 0, err
	}
	pending, err := j.jvm.Exception()
	if err != nil || int32(status) != 0 || pending {
		return uint64(status), err
	}
	j.mu.Lock()
	clear(j.natives)
	j.registeredClass = 0
	j.mu.Unlock()
	_, err = j.jvm.Call(22, false, retained)
	return uint64(status), err
}

func jniPrimitiveWidth(index uint) uint64 {
	return [...]uint64{1, 1, 2, 2, 4, 8, 4, 8}[index]
}

func jniByteCount(length int32, width uint64) (uint64, error) {
	if length < 0 {
		return 0, nil // Bounds/failure precedence is decided by the actual JNI call.
	}
	n := uint64(length) * width
	if n > uint64(int(^uint(0)>>1)) {
		return 0, errors.New("actual JNI buffer exceeds the host addressable slice size")
	}
	return n, nil
}

func (j *GuestJNI) getBuffer(index uint, a [8]uint64) (uint64, error) {
	var lengthIndex, release uint
	width := uint64(1)
	writable := false
	switch {
	case index == 165:
		lengthIndex, release, width = 164, 166, 2
	case index == 169:
		lengthIndex, release = 168, 170
	case index >= 183 && index <= 190:
		lengthIndex, release = 171, index+8
		width, writable = jniPrimitiveWidth(index-183), true
	default:
		return 0, fmt.Errorf("unsupported actual JNI buffer acquisition %d", index)
	}
	length, err := j.jvm.Call(lengthIndex, false, uintptr(a[1]))
	if err != nil {
		return 0, err
	}
	pending, err := j.jvm.Exception()
	if err != nil || pending {
		return 0, err
	}
	if int32(length) < 0 {
		return 0, errors.New("genuine JNI buffer length is negative")
	}
	size, err := jniByteCount(int32(length), width)
	if err != nil {
		return 0, err
	}
	if index == 169 {
		size++ // Genuine JNI modified UTF-8 is NUL-terminated.
	}
	object, err := j.jvm.Call(21, false, uintptr(a[1]))
	if err != nil || object == 0 {
		return 0, err
	}
	var copied uint8
	actual, err := j.jvm.Call(index, false, uintptr(a[1]), uintptr(unsafe.Pointer(&copied)))
	runtime.KeepAlive(&copied)
	if err != nil || actual == 0 {
		j.jvm.Call(22, false, object)
		return 0, err
	}
	buffer := guestJNIBuffer{release: release, object: object, pointer: actual, length: size, writable: writable}
	cleanup := func(guest uint64) error {
		var releaseErr error
		if writable {
			_, releaseErr = j.jvm.Call(release, false, object, actual, 2)
		} else {
			_, releaseErr = j.jvm.Call(release, false, object, actual)
		}
		_, referenceErr := j.jvm.Call(22, false, object)
		if guest != 0 {
			return errors.Join(releaseErr, referenceErr, j.memory.Free(guest))
		}
		return errors.Join(releaseErr, referenceErr)
	}
	allocation := size
	if allocation == 0 {
		allocation = 1
	}
	guest, err := j.memory.Allocate(allocation)
	if err != nil {
		return 0, errors.Join(err, cleanup(0))
	}
	if size != 0 {
		if err := j.memory.Write(guest, unsafe.Slice((*byte)(unsafe.Pointer(actual)), int(size))); err != nil {
			return 0, errors.Join(err, cleanup(guest))
		}
	}
	if a[2] != 0 {
		// Even when HotSpot returns a pinned buffer, ARM64 sees an actual copy.
		copied := [1]byte{1}
		if err := j.memory.Write(a[2], copied[:]); err != nil {
			return 0, errors.Join(err, cleanup(guest))
		}
	}
	j.mu.Lock()
	if _, exists := j.buffers[guest]; exists {
		j.mu.Unlock()
		return 0, errors.Join(errors.New("guest JNI allocator reused a live cross-CPU buffer"), cleanup(0))
	}
	j.buffers[guest] = buffer
	j.mu.Unlock()
	return guest, nil
}

func (j *GuestJNI) releaseBuffer(index uint, a [8]uint64) (uint64, error) {
	j.mu.Lock()
	buffer, exists := j.buffers[a[2]]
	j.mu.Unlock()
	if !exists || buffer.release != index {
		return 0, errors.New("guest JNI released an unowned buffer or mismatched its acquisition type")
	}
	same, err := j.jvm.Call(24, false, buffer.object, uintptr(a[1]))
	if err != nil {
		return 0, err
	}
	if same == 0 {
		return 0, errors.New("guest JNI released a buffer belonging to a different actual Java object")
	}
	mode := int32(a[3])
	if buffer.writable && mode != 0 && mode != 1 && mode != 2 {
		return 0, fmt.Errorf("invalid JNI array release mode %d", mode)
	}
	if buffer.writable && mode != 2 && buffer.length != 0 {
		if err := j.memory.Read(a[2], unsafe.Slice((*byte)(unsafe.Pointer(buffer.pointer)), int(buffer.length))); err != nil {
			return 0, err
		}
	}
	if buffer.writable {
		_, err = j.jvm.Call(index, false, buffer.object, buffer.pointer, uintptr(uint32(mode)))
	} else {
		_, err = j.jvm.Call(index, false, buffer.object, buffer.pointer)
	}
	if err != nil {
		return 0, err
	}
	if !buffer.writable || mode != 1 {
		j.mu.Lock()
		delete(j.buffers, a[2])
		j.mu.Unlock()
		_, err = j.jvm.Call(22, false, buffer.object)
		err = errors.Join(err, j.memory.Free(a[2]))
	}
	return 0, err
}

func (j *GuestJNI) arrayRegion(index uint, a [8]uint64) (uint64, error) {
	set := index >= 207
	ordinal := index - 199
	if set {
		ordinal = index - 207
	}
	size, err := jniByteCount(int32(a[3]), jniPrimitiveWidth(ordinal))
	if err != nil {
		return 0, err
	}
	buffer := make([]byte, max(1, int(size)))
	if set && size != 0 {
		if err := j.memory.Read(a[4], buffer[:int(size)]); err != nil {
			return 0, err
		}
	}
	_, err = j.jvm.Call(index, false, uintptr(a[1]), uintptr(a[2]), uintptr(a[3]), uintptr(unsafe.Pointer(unsafe.SliceData(buffer))))
	runtime.KeepAlive(buffer)
	if err != nil {
		return 0, err
	}
	if !set && size != 0 {
		pending, err := j.jvm.Exception()
		if err != nil {
			return 0, err
		}
		if !pending {
			if err := j.memory.Write(a[4], buffer[:int(size)]); err != nil {
				return 0, err
			}
		}
	}
	return 0, nil
}

func (j *GuestJNI) unicodeString(index uint, a [8]uint64) (uint64, error) {
	lengthArgument, pointerArgument := 2, 1
	if index == 220 {
		lengthArgument, pointerArgument = 3, 4
	}
	size, err := jniByteCount(int32(a[lengthArgument]), 2)
	if err != nil {
		return 0, err
	}
	buffer := make([]byte, max(2, int(size)))
	if index == 163 && size != 0 {
		if err := j.memory.Read(a[pointerArgument], buffer[:int(size)]); err != nil {
			return 0, err
		}
	}
	var value uintptr
	if index == 163 {
		value, err = j.jvm.Call(index, false, uintptr(unsafe.Pointer(unsafe.SliceData(buffer))), uintptr(a[2]))
	} else {
		value, err = j.jvm.Call(index, false, uintptr(a[1]), uintptr(a[2]), uintptr(a[3]), uintptr(unsafe.Pointer(unsafe.SliceData(buffer))))
	}
	runtime.KeepAlive(buffer)
	if err != nil {
		return 0, err
	}
	if index == 220 && size != 0 {
		pending, err := j.jvm.Exception()
		if err != nil {
			return 0, err
		}
		if !pending {
			if err := j.memory.Write(a[pointerArgument], buffer[:int(size)]); err != nil {
				return 0, err
			}
		}
	}
	return uint64(value), nil
}

// Invoke handles every JNI entry exercised by the original full f/c path.
// Other entries are implemented only where the source bridge has a genuine
// fixed/typed ABI; unavailable services fail rather than returning zero stubs.
func (j *GuestJNI) Invoke(index uint, a [8]uint64) (uint64, error) {
	if j == nil || j.jvm == nil || j.memory == nil || j.execute == nil {
		return 0, errors.New("guest JNI genuine dependencies are absent")
	}
	if a[0] != GuestEnvironment {
		return 0, fmt.Errorf("guest JNI entry %d used an unknown environment %#x", index, a[0])
	}
	if (index >= 28 && index <= 30) || (index >= 34 && index <= 93) || (index >= 114 && index <= 143) {
		return j.invokeMethod(index, a)
	}
	if index >= 95 && index <= 103 {
		kind := "LZBCSIJFD"[index-95]
		if err := j.fieldType(uintptr(a[2]), kind, false); err != nil {
			return 0, err
		}
		bits, err := j.call(index, a[1], a[2])
		if err != nil {
			return 0, err
		}
		if kind == 'F' || kind == 'D' {
			if err := j.memory.SetFloatResult(bits, kind == 'D'); err != nil {
				return 0, err
			}
			return a[0], nil
		}
		return bits, nil
	}
	if index >= 145 && index <= 153 {
		kind := "LZBCSIJFD"[index-145]
		if err := j.fieldType(uintptr(a[2]), kind, true); err != nil {
			return 0, err
		}
		bits, err := j.call(index, a[1], a[2])
		if err != nil {
			return 0, err
		}
		if kind == 'F' || kind == 'D' {
			if err := j.memory.SetFloatResult(bits, kind == 'D'); err != nil {
				return 0, err
			}
			return a[0], nil
		}
		return bits, nil
	}
	if (index >= 104 && index <= 110) || (index >= 154 && index <= 160) {
		base, static := uint(104), false
		if index >= 154 {
			base, static = 154, true
		}
		kind := "LZBCSIJ"[index-base]
		if err := j.fieldType(uintptr(a[2]), kind, static); err != nil {
			return 0, err
		}
		return j.call(index, a[1], a[2], jniArgumentBits(a[3], kind))
	}
	if index >= 175 && index <= 182 {
		return j.call(index, a[1])
	}
	if index >= 183 && index <= 190 {
		return j.getBuffer(index, a)
	}
	if index >= 191 && index <= 198 {
		return j.releaseBuffer(index, a)
	}
	if index >= 199 && index <= 214 {
		return j.arrayRegion(index, a)
	}
	switch index {
	case 4, 15, 16, 17, 228:
		return j.call(index)
	case 6, 167:
		text, err := j.memory.String(a[1])
		if err != nil {
			return 0, err
		}
		buffer, err := jniCString(text)
		if err != nil {
			return 0, err
		}
		value, err := j.jvm.Call(index, false, uintptr(unsafe.Pointer(unsafe.SliceData(buffer))))
		runtime.KeepAlive(buffer)
		return uint64(value), err
	case 7, 8, 10, 13, 19, 20, 21, 22, 23, 25, 26, 27, 31, 164, 168, 171, 217, 218, 226, 227, 232:
		return j.call(index, a[1])
	case 9, 12:
		return j.call(index, a[1], a[2], a[3]&255)
	case 11, 24, 32, 173:
		return j.call(index, a[1], a[2])
	case 14:
		message, err := j.memory.String(a[2])
		if err != nil {
			return 0, err
		}
		text, err := jniCString(message)
		if err != nil {
			return 0, err
		}
		value, err := j.jvm.Call(index, false, uintptr(a[1]), uintptr(unsafe.Pointer(unsafe.SliceData(text))))
		runtime.KeepAlive(text)
		return uint64(value), err
	case 33, 94, 113, 144:
		return j.lookup(index, a)
	case 111, 112, 161, 162:
		return 0, fmt.Errorf("ARM64 floating field setter %d requires input S/D registers absent from GuestMemory; no X-register substitution", index)
	case 163, 220:
		return j.unicodeString(index, a)
	case 165, 169:
		return j.getBuffer(index, a)
	case 166, 170:
		return j.releaseBuffer(index, a)
	case 172, 174:
		return j.call(index, a[1], a[2], a[3])
	case 215:
		return j.registerOriginalNatives(uintptr(a[1]), a[2], int32(a[3]))
	case 216:
		return j.unregisterOriginalNatives(uintptr(a[1]))
	case 219:
		if a[1] == 0 {
			return 0, errors.New("guest GetJavaVM output pointer is null")
		}
		var actual uintptr
		status, err := j.jvm.Call(index, false, uintptr(unsafe.Pointer(&actual)))
		runtime.KeepAlive(&actual)
		if err != nil {
			return 0, err
		}
		pointer := uint64(0)
		if actual != 0 {
			pointer = GuestVirtualMachine
		}
		if err := j.writePointer(a[1], pointer); err != nil {
			return 0, err
		}
		return uint64(status), nil
	case 5:
		return 0, errors.New("guest DefineClass is not an original APK class-loading path; no replacement class bodies allowed")
	case 18:
		return 0, errors.New("original guest requested JNI FatalError")
	case 221:
		return 0, errors.New("guest GetStringUTFRegion variable MUTF-8 output ABI is not exercised/supported by the source path")
	case 222, 223, 224, 225:
		return 0, errors.New("guest critical JNI buffers cannot be retained across the cooperative Go/C scheduler")
	case 229, 230, 231:
		return 0, errors.New("guest direct-buffer host-memory ownership is unavailable; no host pointer exposed as ARM64 memory")
	default:
		return 0, fmt.Errorf("original guest requires unsupported real JNI entry %d", index)
	}
}

type jniAttachArguments struct {
	version int32
	padding uint32
	name    uintptr
	group   uintptr
}

// InvokeVM asks the actual current C thread's VM for its actual attachment.
// Detached child GetEnv really returns JNI_EDETACHED; no session/env record is
// manufactured, and Attach/Detach are actual original JavaVM table operations.
func (j *GuestJNI) InvokeVM(index uint, a [8]uint64) (uint64, error) {
	if j == nil || j.jvm == nil || j.memory == nil {
		return 0, errors.New("guest VM genuine dependencies are absent")
	}
	if a[0] != GuestVirtualMachine {
		return 0, fmt.Errorf("guest VM operation used an unknown JavaVM %#x", a[0])
	}
	if index == 5 {
		result, err := j.jvm.Call(5, true)
		return uint64(result), err
	}
	if index != 4 && index != 6 && index != 7 {
		return 0, fmt.Errorf("unsupported original guest JavaVM operation %d", index)
	}
	if a[1] == 0 {
		return 0, errors.New("guest JavaVM environment output pointer is null")
	}
	var actual uintptr
	var attach jniAttachArguments
	var nameText []byte
	extra := uintptr(a[2])
	var pin runtime.Pinner
	defer pin.Unpin()
	if index != 6 {
		extra = 0
		if a[2] != 0 {
			var data [24]byte
			if err := j.memory.Read(a[2], data[:]); err != nil {
				return 0, err
			}
			attach.version = int32(binary.LittleEndian.Uint32(data[0:4]))
			attach.group = uintptr(binary.LittleEndian.Uint64(data[16:24]))
			name := binary.LittleEndian.Uint64(data[8:16])
			if name != 0 {
				text, err := j.memory.String(name)
				if err != nil {
					return 0, err
				}
				nameText, err = jniCString(text)
				if err != nil {
					return 0, err
				}
				pin.Pin(unsafe.SliceData(nameText))
				attach.name = uintptr(unsafe.Pointer(unsafe.SliceData(nameText)))
			}
			pin.Pin(&attach)
			extra = uintptr(unsafe.Pointer(&attach))
		}
	}
	status, err := j.jvm.Call(index, true, uintptr(unsafe.Pointer(&actual)), extra)
	runtime.KeepAlive(&actual)
	runtime.KeepAlive(&attach)
	runtime.KeepAlive(nameText)
	if err != nil {
		return 0, err
	}
	pointer := uint64(0)
	if actual != 0 {
		pointer = GuestEnvironment
	}
	if err := j.writePointer(a[1], pointer); err != nil {
		return 0, err
	}
	return uint64(status), nil
}

// closeHostBuffers runs only after all original native callbacks and C children
// have finished, while the real worker/JVM is still alive. Uncommitted array
// copies are aborted; strings are released, then actual global refs are deleted.
func (j *GuestJNI) closeHostBuffers() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var result error
	for address, buffer := range j.buffers {
		var err error
		if buffer.writable {
			_, err = j.jvm.callWorker(buffer.release, false, buffer.object, buffer.pointer, 2)
		} else {
			_, err = j.jvm.callWorker(buffer.release, false, buffer.object, buffer.pointer)
		}
		result = errors.Join(result, err)
		_, err = j.jvm.callWorker(22, false, buffer.object)
		result = errors.Join(result, err, j.memory.Free(address))
		delete(j.buffers, address)
	}
	if j.registeredClass != 0 {
		_, err := j.jvm.callWorker(22, false, j.registeredClass)
		result = errors.Join(result, err)
		j.registeredClass = 0
	}
	clear(j.natives)
	return result
}
