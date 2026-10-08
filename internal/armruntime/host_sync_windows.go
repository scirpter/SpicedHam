//go:build windows && amd64

package armruntime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

type hostMutex struct {
	lock        sync.Mutex
	owner       uint64
	ownerThread uint32
	depth       uint16
	kind        uint16
}

type hostCondition struct {
	lock      sync.Mutex
	condition *sync.Cond
}

func (h *HostABI) threadOwner() (uint64, error) {
	owner, err := h.memory.ThreadLocal()
	if err != nil {
		return 0, err
	}
	if owner == 0 {
		return 0, errors.New("actual guest synchronization has no thread-local owner")
	}
	return owner, nil
}

func (h *HostABI) writeMutexState(address uint64, mutex *hostMutex) error {
	var state [2]byte
	value := mutex.kind << 14
	if mutex.owner != 0 {
		value |= 1
		if mutex.kind == 1 {
			value |= (mutex.depth - 1) << 2
		}
	}
	binary.LittleEndian.PutUint16(state[:], value)
	if mutex.kind != 0 {
		var thread [4]byte
		binary.LittleEndian.PutUint32(thread[:], mutex.ownerThread)
		if err := h.memory.Write(address+4, thread[:]); err != nil {
			return err
		}
	}
	return h.memory.Write(address, state[:])
}

func (h *HostABI) mutexOperation(name string, address uint64) (uint64, error) {
	if address&3 != 0 {
		return hostEINVAL, nil
	}
	if err := h.validateRange(address, 8); err != nil {
		return 0, err
	}
	var state [2]byte
	if err := h.memory.Read(address, state[:]); err != nil {
		return 0, err
	}
	value := binary.LittleEndian.Uint16(state[:])
	if value == 0xffff {
		return hostEINVAL, nil
	}
	kind := value >> 14
	if kind == 3 || value&0x2000 != 0 {
		return 0, errors.New("guest priority-inheritance/process-shared mutex requires a genuine supported scheduler")
	}
	owner, err := h.threadOwner()
	if err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	mutex := h.mutexes[address]
	if mutex == nil {
		if value&0x1fff != 0 {
			return 0, errors.New("guest mutex arrived locked without an owned host synchronization object")
		}
		mutex = &hostMutex{kind: kind}
		h.mutexes[address] = mutex
	} else if mutex.kind != kind {
		return 0, errors.New("original guest changed a live mutex's type")
	}
	switch name {
	case "pthread_mutex_destroy":
		if mutex.owner != 0 {
			return hostEBUSY, nil
		}
		binary.LittleEndian.PutUint16(state[:], 0xffff)
		if err := h.memory.Write(address, state[:]); err != nil {
			return 0, err
		}
		delete(h.mutexes, address)
		return 0, nil
	case "pthread_mutex_unlock":
		if mutex.owner != owner {
			return hostEPERM, nil
		}
		if mutex.depth > 1 {
			mutex.depth--
			if err := h.writeMutexState(address, mutex); err != nil {
				mutex.depth++
				return 0, err
			}
			return 0, nil
		}
		thread := mutex.ownerThread
		mutex.owner, mutex.ownerThread, mutex.depth = 0, 0, 0
		if err := h.writeMutexState(address, mutex); err != nil {
			mutex.owner, mutex.ownerThread, mutex.depth = owner, thread, 1
			return 0, err
		}
		mutex.lock.Unlock()
		return 0, nil
	case "pthread_mutex_lock", "pthread_mutex_trylock":
		if mutex.owner == owner && mutex.kind == 1 {
			if mutex.depth == 2048 {
				return hostEAGAIN, nil
			}
			mutex.depth++
			if err := h.writeMutexState(address, mutex); err != nil {
				mutex.depth--
				return 0, err
			}
			return 0, nil
		}
		if mutex.owner == owner && mutex.kind == 2 && name == "pthread_mutex_lock" {
			return hostEDEADLK, nil
		}
		if !mutex.lock.TryLock() {
			if name == "pthread_mutex_trylock" {
				return hostEBUSY, nil
			}
			// The owning CPU currently runs a child to completion. Blocking
			// here could never progress a parent that owns this mutex. Actual
			// contention is an explicit missing scheduling operation, not a
			// successful no-op and not an unbounded host deadlock.
			return 0, fmt.Errorf("actual guest mutex contention at %#x requires concurrently progressing guest scheduling", address)
		}
		mutex.owner, mutex.ownerThread, mutex.depth = owner, windows.GetCurrentThreadId(), 1
		if err := h.writeMutexState(address, mutex); err != nil {
			mutex.owner, mutex.ownerThread, mutex.depth = 0, 0, 0
			mutex.lock.Unlock()
			return 0, err
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown guest mutex operation %q", name)
	}
}

func (h *HostABI) conditionOperation(name string, a [8]uint64) (uint64, error) {
	address := a[0]
	if address&3 != 0 {
		return hostEINVAL, nil
	}
	if err := h.validateRange(address, 4); err != nil {
		return 0, err
	}
	owner, err := h.threadOwner()
	if err != nil {
		return 0, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// Serialize the guest sequence word with registration and wakeup, just
	// as bionic's atomic fetch_add does; concurrent signals cannot be lost.
	var state [4]byte
	if err := h.memory.Read(address, state[:]); err != nil {
		return 0, err
	}
	value := binary.LittleEndian.Uint32(state[:])
	if value == 0xffffffff {
		return hostEINVAL, nil
	}
	if value&1 != 0 {
		return 0, errors.New("actual process-shared guest condition has no Windows cross-process adapter")
	}
	condition := h.conditions[address]
	if condition == nil {
		condition = &hostCondition{}
		condition.condition = sync.NewCond(&condition.lock)
		h.conditions[address] = condition
	}
	switch name {
	case "pthread_cond_broadcast", "pthread_cond_signal":
		// Bionic's private condition word advances by four on signal/wake;
		// the low clock/shared bits are retained. Wake a real condition,
		// even when (as in the exercised original f) no waiters exist.
		binary.LittleEndian.PutUint32(state[:], (value+4)&^uint32(3)|value&3)
		if err := h.memory.Write(address, state[:]); err != nil {
			return 0, err
		}
		condition.lock.Lock()
		if name == "pthread_cond_broadcast" {
			condition.condition.Broadcast()
		} else {
			condition.condition.Signal()
		}
		condition.lock.Unlock()
		return 0, nil
	case "pthread_cond_wait":
		mutex := h.mutexes[a[1]]
		if mutex == nil || mutex.owner != owner {
			return hostEPERM, nil
		}
		return 0, errors.New("actual guest condition wait requires concurrently progressing guest scheduling; owned mutex retained on failure")
	case "pthread_cond_destroy":
		binary.LittleEndian.PutUint32(state[:], 0xffffffff)
		if err := h.memory.Write(address, state[:]); err != nil {
			return 0, err
		}
		delete(h.conditions, address)
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown guest condition operation %q", name)
	}
}
