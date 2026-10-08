//go:build windows && amd64

package armruntime

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	regX0  = 199
	regX8  = 207
	regLR  = 2
	regSP  = 4
	regPC  = 260
	regTLS = 262
	regS0  = 136
	regD0  = 40
	regCP  = 290
)

// cpuRuntime owns one real Unicorn engine. It executes only original guest
// bytes; the host JIT allocation adapter does not change guest validation.
type cpuRuntime struct {
	dll                                                           *syscall.DLL
	engine                                                        uintptr
	restoreAllocator                                              func() error
	close, mapMem, unmapMem, writeMem, readMem, writeReg, readReg *syscall.Proc
	readRegisters, run, stop, control, hookAdd                    *syscall.Proc
	contextAlloc, contextSave, contextRestore, contextFree        *syscall.Proc
}

//go:uintptrescapes
func (c *cpuRuntime) invoke(proc *syscall.Proc, arguments ...uintptr) error {
	result, _, _ := proc.Call(arguments...)
	if result != 0 {
		return fmt.Errorf("Unicorn %s: error %d", proc.Name, result)
	}
	return nil
}

func openCPU(path string) (_ *cpuRuntime, err error) {
	dll, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, fmt.Errorf("load CPU runtime: %w", err)
	}
	c := &cpuRuntime{dll: dll}
	defer func() {
		if err != nil {
			_ = c.release()
		}
	}()
	c.restoreAllocator, err = installNativeJITAllocator(c, path)
	if err != nil {
		return nil, err
	}
	bindings := []struct {
		name   string
		target **syscall.Proc
	}{
		{"uc_close", &c.close}, {"uc_mem_map", &c.mapMem}, {"uc_mem_unmap", &c.unmapMem},
		{"uc_mem_write", &c.writeMem}, {"uc_mem_read", &c.readMem},
		{"uc_reg_write", &c.writeReg}, {"uc_reg_read", &c.readReg},
		{"uc_reg_read_batch", &c.readRegisters}, {"uc_emu_start", &c.run},
		{"uc_emu_stop", &c.stop}, {"uc_ctl", &c.control}, {"uc_hook_add", &c.hookAdd},
		{"uc_context_alloc", &c.contextAlloc}, {"uc_context_save", &c.contextSave},
		{"uc_context_restore", &c.contextRestore}, {"uc_context_free", &c.contextFree},
	}
	for _, binding := range bindings {
		*binding.target, err = dll.FindProc(binding.name)
		if err != nil {
			return nil, fmt.Errorf("bind %s: %w", binding.name, err)
		}
	}
	open, err := dll.FindProc("uc_open")
	if err != nil {
		return nil, err
	}
	if err = c.invoke(open, 2, 0, uintptr(unsafe.Pointer(&c.engine))); err != nil {
		return nil, err
	}
	// CPU model must precede all engine operations except uc_open.
	if err = c.invoke(c.control, c.engine, 0x44000007, 0); err != nil {
		return nil, err
	} // audited A57
	if err = c.invoke(c.control, c.engine, 0x4400000d, 64*1024*1024); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *cpuRuntime) release() error {
	var failure error
	if c.engine != 0 && c.close != nil {
		failure = c.invoke(c.close, c.engine)
		c.engine = 0
	}
	if c.restoreAllocator != nil {
		if err := c.restoreAllocator(); failure == nil {
			failure = err
		}
		c.restoreAllocator = nil
	}
	if c.dll != nil {
		if err := c.dll.Release(); failure == nil {
			failure = err
		}
		c.dll = nil
	}
	return failure
}

func (c *cpuRuntime) mapRegion(address, size uint64) error {
	return c.invoke(c.mapMem, c.engine, uintptr(address), uintptr(size), 7)
}
func (c *cpuRuntime) unmapRegion(address, size uint64) error {
	return c.invoke(c.unmapMem, c.engine, uintptr(address), uintptr(size))
}
func (c *cpuRuntime) write(address uint64, source []byte) error {
	if len(source) == 0 {
		return nil
	}
	err := c.invoke(c.writeMem, c.engine, uintptr(address), uintptr(unsafe.Pointer(unsafe.SliceData(source))), uintptr(len(source)))
	runtime.KeepAlive(source)
	return err
}
func (c *cpuRuntime) read(address uint64, target []byte) error {
	if len(target) == 0 {
		return nil
	}
	err := c.invoke(c.readMem, c.engine, uintptr(address), uintptr(unsafe.Pointer(unsafe.SliceData(target))), uintptr(len(target)))
	runtime.KeepAlive(target)
	return err
}
func (c *cpuRuntime) setRegister(id int, value uint64) error {
	err := c.invoke(c.writeReg, c.engine, uintptr(id), uintptr(unsafe.Pointer(&value)))
	runtime.KeepAlive(&value)
	return err
}
func (c *cpuRuntime) register(id int) (uint64, error) {
	var value uint64
	err := c.invoke(c.readReg, c.engine, uintptr(id), uintptr(unsafe.Pointer(&value)))
	runtime.KeepAlive(&value)
	return value, err
}
func (c *cpuRuntime) arguments() ([8]uint64, error) {
	registers := [8]int32{199, 200, 201, 202, 203, 204, 205, 206}
	var values [8]uint64
	var pointers [8]uintptr
	for index := range pointers {
		pointers[index] = uintptr(unsafe.Pointer(&values[index]))
	}
	err := c.invoke(c.readRegisters, c.engine, uintptr(unsafe.Pointer(&registers[0])), uintptr(unsafe.Pointer(&pointers[0])), 8)
	runtime.KeepAlive(registers)
	runtime.KeepAlive(pointers)
	runtime.KeepAlive(&values)
	return values, err
}
func (c *cpuRuntime) coprocessor(crn, crm, op2 uint32) (uint64, error) {
	// Layout is the actual installed uc_arm64_cp_reg, including uint64 alignment.
	value := struct {
		Crn, Crm, Op0, Op1, Op2 uint32
		Value                   uint64
	}{Crn: crn, Crm: crm, Op0: 3, Value: 0, Op2: op2}
	err := c.invoke(c.readReg, c.engine, regCP, uintptr(unsafe.Pointer(&value)))
	runtime.KeepAlive(&value)
	return value.Value, err
}
func (c *cpuRuntime) saveContext() (uintptr, error) {
	var context uintptr
	if err := c.invoke(c.contextAlloc, c.engine, uintptr(unsafe.Pointer(&context))); err != nil {
		return 0, err
	}
	if err := c.invoke(c.contextSave, c.engine, context); err != nil {
		_ = c.invoke(c.contextFree, context)
		return 0, err
	}
	return context, nil
}
func (c *cpuRuntime) addHook(kind int, callback uintptr, begin, end uint64) error {
	var handle uintptr
	err := c.invoke(c.hookAdd, c.engine, uintptr(unsafe.Pointer(&handle)), uintptr(kind), callback, 0, uintptr(begin), uintptr(end))
	runtime.KeepAlive(&handle)
	return err
}
