//go:build windows && amd64

package armruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"unsafe"
)

const (
	imageBase uint64 = 0x1000000
	stackBase uint64 = 0x4000000
	stubBase  uint64 = 0x6000000
	stopPC    uint64 = stubBase + 0xf000
	jniTable  uint64 = GuestEnvironment + 0x1000
	vmTable   uint64 = GuestEnvironment + 0x2000
	mainTLS   uint64 = GuestEnvironment + 0x3000
	heapBase  uint64 = 0x8000000
	heapSize  uint64 = 0x1000000
	imageSHA         = "58cbfa1c00d4d75850bf020a2799e9a05d99984e1413391cea810a7879f420cd"
)

type Config struct {
	CPU, NativeLibrary string
	JVM                JVMConfig
	Application        *HostApplicationConfig
}

type operation struct {
	kind  uint
	index uint
	name  string
}
type memoryRange struct{ address, size uint64 }
type guestThread struct {
	callback uintptr
	region   uint64
}

// Runtime owns the selected account's original native execution state. Calls
// are serialized; it cannot be shared as another account's session provider.
// An optional plain Windows Application supplies only its real owned scope;
// unavailable Android installation/services/properties remain observable.
type Runtime struct {
	gate             sync.Mutex
	cpu              *cpuRuntime
	jvm              *JVM
	jni              *GuestJNI
	host             *HostABI
	closed           bool
	failure          error
	operations       map[uint64]operation
	nextStub         uint64
	symbols          map[string]uint64
	imports          map[string]uint64
	allocations      map[uint64]uint64
	free             []memoryRange
	initializers     []uint64
	callbacks        []uintptr
	pending          *[8]uint64
	threads          map[uintptr]guestThread
	nextThreadMemory uint64
}

func Open(config Config) (_ *Runtime, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if config.CPU == "" || config.NativeLibrary == "" {
		return nil, errors.New("original CPU runtime and APK library paths are required")
	}
	r := &Runtime{operations: make(map[uint64]operation), nextStub: stubBase, symbols: make(map[string]uint64), imports: make(map[string]uint64), allocations: make(map[uint64]uint64), free: []memoryRange{{heapBase, heapSize}}, threads: make(map[uintptr]guestThread), nextThreadMemory: 0xa000000}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.Close())
		}
	}()
	r.jvm, err = openJVM(config.JVM, config.Application)
	if err != nil {
		return nil, err
	}
	r.cpu, err = openCPU(config.CPU)
	if err != nil {
		return nil, err
	}
	// Capabilities are read from the actual configured guest CPU, not handset data.
	isar0, err := r.cpu.coprocessor(0, 6, 0)
	if err != nil {
		return nil, err
	}
	isar1, err := r.cpu.coprocessor(0, 6, 1)
	if err != nil {
		return nil, err
	}
	pfr0, err := r.cpu.coprocessor(0, 4, 0)
	if err != nil {
		return nil, err
	}
	if isar0 != 0x11120 || isar1 != 0 || pfr0 != 0x2222 {
		return nil, errors.New("actual emulated A57 capabilities differ from audited runtime")
	}
	hwcap := uint64(0)
	if pfr0>>16&15 != 15 {
		hwcap |= 1
	}
	if pfr0>>20&15 != 15 {
		hwcap |= 2
	}
	for _, feature := range [][3]uint{{4, 1, 3}, {4, 2, 4}, {8, 1, 5}, {12, 1, 6}, {16, 1, 7}, {20, 2, 8}} {
		if isar0>>feature[0]&15 >= uint64(feature[1]) {
			hwcap |= 1 << feature[2]
		}
	}
	for _, region := range [][2]uint64{{stackBase, 0x100000}, {stubBase, 0x10000}, {GuestEnvironment, 0x10000}, {heapBase, heapSize}} {
		if err = r.cpu.mapRegion(region[0], region[1]); err != nil {
			return nil, err
		}
	}
	if err = r.cpu.setRegister(regTLS, mainTLS); err != nil {
		return nil, err
	}
	if err = r.initializeTLS(mainTLS); err != nil {
		return nil, err
	}
	r.host, err = NewHostABI(r, map[uint64]uint64{16: hwcap, 26: 0})
	if err != nil {
		return nil, err
	}
	r.host.SetGuestExecutor(r.execute)
	r.jni = NewGuestJNI(r.jvm, r, r.execute)
	if err = r.setupHooks(); err != nil {
		return nil, err
	}
	if err = r.loadImage(config.NativeLibrary); err != nil {
		return nil, err
	}
	for _, address := range r.initializers {
		if _, err = r.execute(address, [8]uint64{}); err != nil {
			return nil, fmt.Errorf("original ELF constructor %#x: %w", address-imageBase, err)
		}
	}
	version, err := r.execute(imageBase+0x1082f4, [8]uint64{GuestVirtualMachine})
	if err != nil {
		return nil, fmt.Errorf("original JNI_OnLoad: %w", err)
	}
	if version != 0x10006 || len(r.jni.NativeMethods()) != 4 {
		return nil, errors.New("original JNI_OnLoad did not register the complete original native ABI")
	}
	if err = r.jvm.InitializeAccumulator(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Runtime) initializeTLS(address uint64) error {
	var canary [8]byte
	if _, err := rand.Read(canary[:]); err != nil {
		return err
	}
	return r.Write(address+0x28, canary[:])
}
func (r *Runtime) Read(address uint64, target []byte) error  { return r.cpu.read(address, target) }
func (r *Runtime) Write(address uint64, source []byte) error { return r.cpu.write(address, source) }
func (r *Runtime) ThreadLocal() (uint64, error)              { return r.cpu.register(regTLS) }
func (r *Runtime) SetFloatResult(bits uint64, wide bool) error {
	if wide {
		return r.cpu.setRegister(regD0, bits)
	}
	return r.cpu.setRegister(regS0, bits)
}
func (r *Runtime) String(address uint64) (string, error) {
	if address == 0 {
		return "", errors.New("required guest C string is null")
	}
	var value []byte
	var block [64]byte
	for len(value) < 65536 {
		// A block must not read across an unmapped page after a valid terminator.
		count := min(len(block), int(4096-(address+uint64(len(value)))%4096))
		if err := r.Read(address+uint64(len(value)), block[:count]); err != nil {
			return "", err
		}
		if end := bytes.IndexByte(block[:count], 0); end >= 0 {
			value = append(value, block[:end]...)
			return string(value), nil
		}
		value = append(value, block[:count]...)
	}
	return "", errors.New("unterminated guest C string")
}
func (r *Runtime) Allocate(size uint64) (uint64, error) {
	if size == 0 {
		size = 1
	}
	if size > heapSize {
		return 0, errors.New("guest allocation exceeds owned native heap")
	}
	size = (size + 15) &^ 15
	for index, space := range r.free {
		if space.size < size {
			continue
		}
		r.allocations[space.address] = size
		if space.size == size {
			r.free = append(r.free[:index], r.free[index+1:]...)
		} else {
			r.free[index].address += size
			r.free[index].size -= size
		}
		return space.address, nil
	}
	return 0, errors.New("guest native heap exhausted")
}
func (r *Runtime) Free(address uint64) error {
	if address == 0 {
		return nil
	}
	size, present := r.allocations[address]
	if !present {
		return errors.New("guest free does not own this allocation")
	}
	var zero [4096]byte
	for cleared := uint64(0); cleared < size; {
		count := min(uint64(len(zero)), size-cleared)
		if err := r.Write(address+cleared, zero[:count]); err != nil {
			return err
		}
		cleared += count
	}
	delete(r.allocations, address)
	r.free = append(r.free, memoryRange{address, size})
	sort.Slice(r.free, func(i, j int) bool { return r.free[i].address < r.free[j].address })
	merged := r.free[:0]
	for _, space := range r.free {
		if len(merged) > 0 && merged[len(merged)-1].address+merged[len(merged)-1].size == space.address {
			merged[len(merged)-1].size += space.size
		} else {
			merged = append(merged, space)
		}
	}
	r.free = merged
	return nil
}
func (r *Runtime) DynamicSymbol(name string) (uint64, bool) {
	address, present := r.symbols[name]
	return address, present
}
func (r *Runtime) ImportAddress(name string) (uint64, error) {
	if address, present := r.imports[name]; present {
		return address, nil
	}
	address, err := r.newOperation(operation{kind: 3, name: name})
	if err == nil {
		r.imports[name] = address
	}
	return address, err
}
func (r *Runtime) newOperation(op operation) (uint64, error) {
	if r.nextStub >= stopPC {
		return 0, errors.New("guest ABI table exhausted")
	}
	address := r.nextStub
	r.nextStub += 4
	if err := r.Write(address, []byte{0xc0, 0x03, 0x5f, 0xd6}); err != nil {
		return 0, err
	}
	r.operations[address] = op
	return address, nil
}
func (r *Runtime) writePointer(address, value uint64) error {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	return r.Write(address, data[:])
}
func (r *Runtime) setupHooks() error {
	if err := r.writePointer(GuestEnvironment, jniTable); err != nil {
		return err
	}
	if err := r.writePointer(GuestVirtualMachine, vmTable); err != nil {
		return err
	}
	for index := uint(4); index < 233; index++ {
		address, err := r.newOperation(operation{kind: 1, index: index})
		if err != nil {
			return err
		}
		if err = r.writePointer(jniTable+uint64(index)*8, address); err != nil {
			return err
		}
	}
	for index := uint(3); index < 8; index++ {
		address, err := r.newOperation(operation{kind: 2, index: index})
		if err != nil {
			return err
		}
		if err = r.writePointer(vmTable+uint64(index)*8, address); err != nil {
			return err
		}
	}
	code := syscall.NewCallback(func(engine, address, size, user uintptr) uintptr {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		a, err := r.cpu.arguments()
		var result uint64
		if err == nil {
			op, present := r.operations[uint64(address)]
			if !present {
				err = fmt.Errorf("unknown original guest ABI entry %#x", address)
			} else {
				switch op.kind {
				case 1:
					result, err = r.jni.Invoke(op.index, a)
				case 2:
					result, err = r.jni.InvokeVM(op.index, a)
				case 3:
					result, err = r.host.Invoke(op.name, a)
				default:
					err = errors.New("invalid guest ABI category")
				}
			}
		}
		if err == nil {
			err = r.cpu.setRegister(regX0, result)
		}
		if err != nil {
			r.fail(err)
		}
		return 0
	})
	intr := syscall.NewCallback(func(engine, number, user uintptr) uintptr {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if number != 2 {
			r.fail(fmt.Errorf("actual guest CPU exception %d", number))
			return 0
		}
		a, err := r.cpu.arguments()
		var call, result uint64
		if err == nil {
			call, err = r.cpu.register(regX8)
		}
		if err == nil {
			result, err = r.host.Syscall(call, a)
		}
		if err == nil {
			err = r.cpu.setRegister(regX0, result)
		}
		if err != nil {
			r.fail(err)
		}
		return 0
	})
	invalid := syscall.NewCallback(func(engine, access, address, size, value, user uintptr) uintptr {
		pc, _ := r.cpu.register(regPC)
		r.fail(fmt.Errorf("original native memory fault: access=%d address=%#x size=%d PC=%#x; not mapped or patched", access, address, size, pc-imageBase))
		return 0
	})
	r.callbacks = []uintptr{code, intr, invalid}
	if err := r.cpu.addHook(4, code, stubBase, stopPC-1); err != nil {
		return err
	}
	if err := r.cpu.addHook(1, intr, 1, 0); err != nil {
		return err
	}
	return r.cpu.addHook(1008, invalid, 1, 0)
}
func (r *Runtime) fail(err error) {
	if r.failure == nil {
		r.failure = err
	}
	_ = r.cpu.invoke(r.cpu.stop, r.cpu.engine)
}

func (r *Runtime) loadImage(path string) error {
	image, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(image)
	if hex.EncodeToString(digest[:]) != imageSHA {
		return errors.New("native ABI is verified only for the current unmodified APK libscplugin.so")
	}
	file, err := elf.NewFile(bytes.NewReader(image))
	if err != nil {
		return err
	}
	defer file.Close()
	if file.Machine != elf.EM_AARCH64 || file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB {
		return errors.New("native image must be little-endian ARM64 ELF")
	}
	var end uint64
	for _, part := range file.Progs {
		if part.Type == elf.PT_LOAD && part.Vaddr+part.Memsz > end {
			end = part.Vaddr + part.Memsz
		}
	}
	if end == 0 || end > 0x1000000 {
		return errors.New("unexpected native image extent")
	}
	if err = r.cpu.mapRegion(imageBase, (end+4095)&^4095); err != nil {
		return err
	}
	for _, part := range file.Progs {
		if part.Type != elf.PT_LOAD {
			continue
		}
		if part.Off > uint64(len(image)) || part.Filesz > uint64(len(image))-part.Off {
			return errors.New("native ELF segment exceeds input")
		}
		if err = r.Write(imageBase+part.Vaddr, image[part.Off:part.Off+part.Filesz]); err != nil {
			return err
		}
	}
	symbols, err := file.DynamicSymbols()
	if err != nil {
		return err
	}
	for _, symbol := range symbols {
		if symbol.Name != "" && symbol.Section != elf.SHN_UNDEF && (elf.ST_BIND(symbol.Info) == elf.STB_GLOBAL || elf.ST_BIND(symbol.Info) == elf.STB_WEAK) && elf.ST_VISIBILITY(symbol.Other) == elf.STV_DEFAULT {
			r.symbols[symbol.Name] = imageBase + symbol.Value
		}
	}
	for _, section := range file.Sections {
		if section.Type != elf.SHT_RELA {
			continue
		}
		relocations, err := section.Data()
		if err != nil {
			return err
		}
		if len(relocations)%24 != 0 {
			return errors.New("invalid native RELA layout")
		}
		for offset := 0; offset < len(relocations); offset += 24 {
			entry := relocations[offset : offset+24]
			address := binary.LittleEndian.Uint64(entry)
			info := binary.LittleEndian.Uint64(entry[8:])
			addend := binary.LittleEndian.Uint64(entry[16:])
			var value uint64
			switch uint32(info) {
			case 1027:
				value = imageBase + addend
			case 1025, 1026:
				index := info >> 32
				// debug/elf omits ELF's null dynamic symbol at index zero.
				if index == 0 || index > uint64(len(symbols)) {
					return errors.New("invalid native dynamic symbol index")
				}
				symbol := symbols[index-1]
				if symbol.Section != elf.SHN_UNDEF {
					value = imageBase + symbol.Value
				} else if symbol.Name == "environ" || symbol.Name == "__progname" {
					value, err = r.host.RelocateData(symbol.Name)
				} else {
					value, err = r.ImportAddress(symbol.Name)
				}
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported original ARM64 ELF relocation %d", uint32(info))
			}
			if err = r.writePointer(imageBase+address, value); err != nil {
				return err
			}
		}
	}
	section := file.Section(".init_array")
	if section == nil || section.Size%8 != 0 {
		return errors.New("original native initializer table missing")
	}
	data := make([]byte, section.Size)
	if err = r.Read(imageBase+section.Addr, data); err != nil {
		return err
	}
	for offset := 0; offset < len(data); offset += 8 {
		r.initializers = append(r.initializers, binary.LittleEndian.Uint64(data[offset:]))
	}
	return nil
}

func (r *Runtime) execute(address uint64, arguments [8]uint64) (uint64, error) {
	return r.executeOn(address, arguments, stackBase+0xf0000, 0)
}
func (r *Runtime) executeOn(address uint64, arguments [8]uint64, stack, tls uint64) (uint64, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r.failure = nil
	if err := r.cpu.setRegister(regSP, stack); err != nil {
		return 0, err
	}
	if tls != 0 {
		if err := r.cpu.setRegister(regTLS, tls); err != nil {
			return 0, err
		}
	}
	if err := r.cpu.setRegister(regLR, stopPC); err != nil {
		return 0, err
	}
	for index, value := range arguments {
		if err := r.cpu.setRegister(regX0+index, value); err != nil {
			return 0, err
		}
	}
	for {
		if err := r.cpu.invoke(r.cpu.run, r.cpu.engine, uintptr(address), uintptr(stopPC), 60_000_000, 100_000_000); err != nil {
			if r.failure != nil {
				return 0, r.failure
			}
			pc, _ := r.cpu.register(regPC)
			return 0, fmt.Errorf("original ARM64 execution PC=%#x: %w", pc-imageBase, err)
		}
		if r.failure != nil {
			return 0, r.failure
		}
		if r.pending == nil {
			break
		}
		if err := r.runPendingThread(); err != nil {
			return 0, err
		}
		var err error
		address, err = r.cpu.register(regPC)
		if err != nil {
			return 0, err
		}
	}
	pc, err := r.cpu.register(regPC)
	if err != nil {
		return 0, err
	}
	if pc != stopPC {
		return 0, errors.New("original native call exhausted its instruction/time limit")
	}
	return r.cpu.register(regX0)
}
func (r *Runtime) CreateGuestThread(arguments [8]uint64) (uint64, error) {
	if arguments[1] != 0 {
		return 0, errors.New("original guest pthread attributes need a genuine layout adapter")
	}
	if r.pending != nil {
		return 0, errors.New("overlapping original guest pthread creation")
	}
	r.pending = &arguments
	return 0, r.cpu.invoke(r.cpu.stop, r.cpu.engine)
}
func (r *Runtime) runPendingThread() error {
	args := *r.pending
	r.pending = nil
	parent, err := r.cpu.saveContext()
	if err != nil {
		return err
	}
	defer r.cpu.invoke(r.cpu.contextFree, parent)
	parentPC, err := r.cpu.register(regLR)
	if err != nil {
		return err
	}
	region := r.nextThreadMemory
	r.nextThreadMemory += 0x200000
	if err = r.cpu.mapRegion(region, 0x110000); err != nil {
		return err
	}
	tls := region + 0x100000
	if err = r.initializeTLS(tls); err != nil {
		return err
	}
	var childError error
	callback := syscall.NewCallback(func(argument uintptr) uintptr {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		result, err := r.executeOn(args[2], [8]uint64{uint64(argument)}, region+0xf0000, tls)
		childError = err
		return uintptr(result)
	})
	thread, err := r.jvm.StartGuestThread(callback, uintptr(args[3]))
	if err != nil {
		_ = r.cpu.invoke(r.cpu.contextRestore, r.cpu.engine, parent)
		_ = r.cpu.unmapRegion(region, 0x110000)
		if reset := r.cpu.setRegister(regPC, parentPC); reset != nil {
			return reset
		}
		return r.cpu.setRegister(regX0, 11) // actual CreateThread failure/EAGAIN
	}
	r.threads[thread] = guestThread{callback, region}
	_, err = r.jvm.WaitGuestThread(thread)
	if err != nil {
		return err
	}
	if err = r.cpu.invoke(r.cpu.contextRestore, r.cpu.engine, parent); err != nil {
		return err
	}
	if err = r.cpu.setRegister(regPC, parentPC); err != nil {
		return err
	}
	if err = r.cpu.setRegister(regX0, 0); err != nil {
		return err
	}
	if err = r.writePointer(args[0], uint64(thread)); err != nil {
		return err
	}
	return childError
}
func (r *Runtime) JoinGuestThread(arguments [8]uint64) (uint64, error) {
	thread, owned := r.threads[uintptr(arguments[0])]
	if !owned {
		return 3, nil
	}
	value, err := r.jvm.JoinGuestThread(uintptr(arguments[0]))
	if err != nil {
		return 0, err
	}
	delete(r.threads, uintptr(arguments[0]))
	if arguments[1] != 0 {
		if err = r.writePointer(arguments[1], uint64(value)); err != nil {
			return 0, err
		}
	}
	return 0, r.cpu.unmapRegion(thread.region, 0x110000)
}

// Attest executes the original registered f on the caller's actual nk9 input.
// Local bytes alone are not accepted server authentication or attestation.
func (r *Runtime) Attest(ctx context.Context, input []byte) ([]byte, error) {
	return r.invokeBytes(ctx, 1, input, "")
}

// Sign executes original c on raw server token bytes and the exact RPC path.
func (r *Runtime) Sign(ctx context.Context, token []byte, path string) ([]byte, error) {
	if len(token) == 0 || path == "" {
		return nil, errors.New("original c requires raw token bytes and actual request path")
	}
	return r.invokeBytes(ctx, 2, token, path)
}
func (r *Runtime) invokeBytes(ctx context.Context, identifier uint, input []byte, path string) (_ []byte, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	r.gate.Lock()
	defer r.gate.Unlock()
	if r.closed || r.jvm == nil {
		return nil, errors.New("native account runtime is closed")
	}
	class, err := r.jvm.Class("vkt/h")
	if err != nil {
		return nil, err
	}
	defer r.jvm.Call(23, false, class)
	name, descriptor := "f", "([B)[B"
	if identifier == 2 {
		name, descriptor = "c", "([BLjava/lang/String;)[B"
	}
	method, err := r.jvm.Method(class, name, descriptor, true)
	if err != nil {
		return nil, err
	}
	source, err := r.jvm.Call(176, false, uintptr(len(input)))
	if err != nil || source == 0 {
		return nil, errors.Join(err, errors.New("real JNI byte array allocation failed"))
	}
	defer r.jvm.Call(23, false, source)
	if len(input) > 0 {
		_, err = r.jvm.Call(208, false, source, 0, uintptr(len(input)), uintptr(unsafe.Pointer(unsafe.SliceData(input))))
		runtime.KeepAlive(input)
		if err != nil {
			return nil, err
		}
	}
	arguments := [2]uint64{uint64(source)}
	if identifier == 2 {
		text := append([]byte(path), 0)
		object, callErr := r.jvm.Call(167, false, uintptr(unsafe.Pointer(unsafe.SliceData(text))))
		runtime.KeepAlive(text)
		if callErr != nil || object == 0 {
			return nil, errors.Join(callErr, errors.New("real JNI request-path string allocation failed"))
		}
		defer r.jvm.Call(23, false, object)
		arguments[1] = uint64(object)
	}
	result, err := r.jvm.Call(116, false, class, method, uintptr(unsafe.Pointer(&arguments[0])))
	runtime.KeepAlive(&arguments)
	if err != nil {
		return nil, err
	}
	if result != 0 {
		defer r.jvm.Call(23, false, result)
	}
	if callbackErr := r.jni.Failure(); callbackErr != nil {
		return nil, callbackErr
	}
	pending, err := r.jvm.Exception()
	if err != nil {
		return nil, err
	}
	if pending {
		_, _ = r.jvm.Call(16, false)
		return nil, errors.New("original native operation raised a real Java exception; platform state was not faked")
	}
	if result == 0 {
		return nil, errors.New("original native operation returned null")
	}
	length, err := r.jvm.Call(171, false, result)
	if err != nil {
		return nil, err
	}
	if length == 0 || length > 16*1024*1024 {
		return nil, errors.New("original native output has unusable byte length")
	}
	output := make([]byte, length)
	_, err = r.jvm.Call(200, false, result, 0, length, uintptr(unsafe.Pointer(unsafe.SliceData(output))))
	runtime.KeepAlive(output)
	if err != nil {
		clear(output)
		return nil, err
	}
	pending, err = r.jvm.Exception()
	if err != nil || pending {
		clear(output)
		return nil, errors.Join(err, errors.New("original native result could not be read without Java exception"))
	}
	if err = ctx.Err(); err != nil {
		clear(output)
		return nil, err
	}
	return output, nil
}

func (r *Runtime) Close() error {
	r.gate.Lock()
	defer r.gate.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var failures []error
	if r.jvm != nil {
		for handle, thread := range r.threads {
			_, err := r.jvm.JoinGuestThread(handle)
			failures = append(failures, err)
			if r.cpu != nil {
				failures = append(failures, r.cpu.unmapRegion(thread.region, 0x110000))
			}
			delete(r.threads, handle)
		}
	}
	if r.host != nil {
		failures = append(failures, r.host.Close())
	}
	if r.jvm != nil {
		failures = append(failures, r.jvm.Close())
		r.jvm = nil
	}
	if r.cpu != nil {
		failures = append(failures, r.cpu.release())
		r.cpu = nil
	}
	return errors.Join(failures...)
}
