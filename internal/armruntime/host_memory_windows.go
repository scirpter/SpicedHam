//go:build windows && amd64

package armruntime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

type hostAllocation struct {
	length   uint64
	capacity uint64
	internal bool
}

type hostAllocationFailure struct{ cause error }

func (e *hostAllocationFailure) Error() string { return e.cause.Error() }
func (e *hostAllocationFailure) Unwrap() error { return e.cause }

// The owning CPU reclaims/coalesces backing ranges through GuestMemory.Free.
// This layer additionally owns C allocation identity and logical object bounds.
func (h *HostABI) allocateLocked(length uint64, internal bool) (uint64, error) {
	if length == 0 {
		length = 1
	}
	if length > math.MaxInt64-15 {
		return 0, &hostAllocationFailure{errors.New("guest allocation length exceeds ARM64 ptrdiff_t")}
	}
	capacity := (length + 15) &^ uint64(15)
	address, err := h.memory.Allocate(capacity)
	if err != nil {
		return 0, &hostAllocationFailure{err}
	}
	if address == 0 || address&15 != 0 || address > math.MaxUint64-capacity {
		return 0, errors.Join(errors.New("guest allocator returned an invalid or unaligned owned range"), h.memory.Free(address))
	}
	index := sort.Search(len(h.allocationOrder), func(i int) bool { return h.allocationOrder[i] >= address })
	if index < len(h.allocationOrder) && h.allocationOrder[index] < address+capacity {
		return 0, errors.New("guest allocator returned an overlapping owned allocation")
	}
	if index > 0 {
		previous := h.allocationOrder[index-1]
		if h.allocations[previous].capacity > address-previous {
			return 0, errors.New("guest allocator returned an overlapping owned allocation")
		}
	}
	h.allocations[address] = hostAllocation{length, capacity, internal}
	h.allocationOrder = append(h.allocationOrder, 0)
	copy(h.allocationOrder[index+1:], h.allocationOrder[index:])
	h.allocationOrder[index] = address
	return address, nil
}

func (h *HostABI) allocateTextLocked(text string) (uint64, error) {
	data := make([]byte, len(text)+1)
	copy(data, text)
	address, err := h.allocateLocked(uint64(len(data)), true)
	if err != nil {
		return 0, err
	}
	if err := h.memory.Write(address, data); err != nil {
		return 0, errors.Join(err, h.releaseAllocationLocked(address, true))
	}
	return address, nil
}

func (h *HostABI) malloc(length uint64, zero bool) (uint64, error) {
	h.mu.Lock()
	address, err := h.allocateLocked(length, false)
	h.mu.Unlock()
	if err != nil {
		var failure *hostAllocationFailure
		if errors.As(err, &failure) {
			return 0, h.setErrno(hostENOMEM)
		}
		return 0, err
	}
	if zero && length != 0 {
		if err := h.fill(address, length, 0); err != nil {
			return 0, errors.Join(err, h.releaseAllocation(address, false))
		}
	}
	return address, nil
}

func (h *HostABI) releaseAllocation(address uint64, internal bool) error {
	if address == 0 {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.releaseAllocationLocked(address, internal)
}

func (h *HostABI) releaseAllocationLocked(address uint64, internal bool) error {
	allocation, ok := h.allocations[address]
	if !ok || allocation.internal != internal {
		return fmt.Errorf("guest free does not own allocation %#x", address)
	}
	if err := h.memory.Free(address); err != nil {
		return fmt.Errorf("reclaim actual guest allocation %#x: %w", address, err)
	}
	delete(h.allocations, address)
	index := sort.Search(len(h.allocationOrder), func(i int) bool { return h.allocationOrder[i] >= address })
	copy(h.allocationOrder[index:], h.allocationOrder[index+1:])
	h.allocationOrder = h.allocationOrder[:len(h.allocationOrder)-1]
	return nil
}

func (h *HostABI) realloc(address, length uint64) (uint64, error) {
	if address == 0 {
		return h.malloc(length, false)
	}
	h.mu.Lock()
	old, ok := h.allocations[address]
	if !ok || old.internal {
		h.mu.Unlock()
		return 0, fmt.Errorf("guest realloc does not own allocation %#x", address)
	}
	if length == 0 {
		err := h.releaseAllocationLocked(address, false)
		h.mu.Unlock()
		return 0, err
	}
	if length <= old.capacity {
		old.length = length
		h.allocations[address] = old
		h.mu.Unlock()
		return address, nil
	}
	updated, err := h.allocateLocked(length, false)
	h.mu.Unlock()
	if err != nil {
		var failure *hostAllocationFailure
		if errors.As(err, &failure) {
			// A failed realloc must retain the caller's original allocation.
			return 0, h.setErrno(hostENOMEM)
		}
		return 0, err
	}
	if err := h.copyMemory(updated, address, old.length, false); err != nil {
		return 0, errors.Join(err, h.releaseAllocation(updated, false))
	}
	if err := h.releaseAllocation(address, false); err != nil {
		return 0, errors.Join(err, h.releaseAllocation(updated, false))
	}
	return updated, nil
}

func (h *HostABI) validateRange(address, length uint64) error {
	if length == 0 {
		return nil
	}
	if address == 0 || address > math.MaxUint64-length {
		return fmt.Errorf("invalid guest byte range %#x + %#x", address, length)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	index := sort.Search(len(h.allocationOrder), func(i int) bool { return h.allocationOrder[i] > address })
	if index > 0 {
		start := h.allocationOrder[index-1]
		allocation := h.allocations[start]
		if address-start < allocation.capacity {
			if address-start >= allocation.length || length > allocation.length-(address-start) {
				return fmt.Errorf("guest byte range exceeds owned allocation %#x (length %d)", start, allocation.length)
			}
			return nil
		}
	}
	if index < len(h.allocationOrder) && h.allocationOrder[index]-address < length {
		return errors.New("guest byte range crosses into a distinct owned allocation")
	}
	// Stack, TLS, ELF and parent/JNI-owned ranges are checked by GuestMemory.
	return nil
}

func (h *HostABI) readMemory(address uint64, target []byte) error {
	if len(target) == 0 {
		return nil
	}
	if err := h.validateRange(address, uint64(len(target))); err != nil {
		return err
	}
	return h.memory.Read(address, target)
}

func (h *HostABI) writeMemory(address uint64, source []byte) error {
	if len(source) == 0 {
		return nil
	}
	if err := h.validateRange(address, uint64(len(source))); err != nil {
		return err
	}
	return h.memory.Write(address, source)
}

func (h *HostABI) writeUint64(address, value uint64) error {
	var bytes [8]byte
	binary.LittleEndian.PutUint64(bytes[:], value)
	return h.writeMemory(address, bytes[:])
}

func (h *HostABI) cString(address uint64) (string, error) {
	if err := h.validateRange(address, 1); err != nil {
		return "", err
	}
	text, err := h.memory.String(address)
	if err != nil {
		return "", err
	}
	if len(text) >= 65536 {
		return "", errors.New("original guest C string exceeds the source's 65536-byte bound")
	}
	if err := h.validateRange(address, uint64(len(text))+1); err != nil {
		return "", err
	}
	return text, nil
}

func (h *HostABI) fill(address, length uint64, value byte) error {
	if err := h.validateRange(address, length); err != nil {
		return err
	}
	var scratch [4096]byte
	amount := min(length, uint64(len(scratch)))
	if value != 0 {
		for index := range scratch[:amount] {
			scratch[index] = value
		}
	}
	for offset := uint64(0); offset < length; {
		amount = min(length-offset, uint64(len(scratch)))
		if err := h.memory.Write(address+offset, scratch[:amount]); err != nil {
			return err
		}
		offset += amount
	}
	return nil
}

func (h *HostABI) copyMemory(destination, source, length uint64, move bool) error {
	if err := h.validateRange(source, length); err != nil {
		return err
	}
	if err := h.validateRange(destination, length); err != nil {
		return err
	}
	if length == 0 || destination == source {
		return nil
	}
	overlap := destination > source && destination-source < length || source > destination && source-destination < length
	if overlap && !move {
		return errors.New("original memcpy requested overlapping guest objects")
	}
	var scratch [4096]byte
	if move && destination > source && destination-source < length {
		for left := length; left != 0; {
			amount := min(left, uint64(len(scratch)))
			left -= amount
			if err := h.memory.Read(source+left, scratch[:amount]); err != nil {
				return err
			}
			if err := h.memory.Write(destination+left, scratch[:amount]); err != nil {
				return err
			}
		}
		return nil
	}
	for offset := uint64(0); offset < length; {
		amount := min(length-offset, uint64(len(scratch)))
		if err := h.memory.Read(source+offset, scratch[:amount]); err != nil {
			return err
		}
		if err := h.memory.Write(destination+offset, scratch[:amount]); err != nil {
			return err
		}
		offset += amount
	}
	return nil
}
