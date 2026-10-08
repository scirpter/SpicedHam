//go:build windows && amd64

// Package armruntime runs the original APK's ARM64 library through a CPU-only
// runtime and the genuine desktop JVM. It does not supply an Android device,
// fabricate platform services, or establish server acceptance by producing bytes.
package armruntime

const (
	GuestEnvironment    uint64 = 0x7000000
	GuestVirtualMachine uint64 = GuestEnvironment + 0x100
)

// GuestMemory separates the ARM64 address space from actual host/JVM pointers.
// Cross-CPU copies are explicit; unknown services must fail, never synthesize data.
type GuestMemory interface {
	Read(address uint64, target []byte) error
	Write(address uint64, source []byte) error
	Allocate(size uint64) (uint64, error)
	String(address uint64) (string, error)
	Free(address uint64) error
	SetFloatResult(bits uint64, wide bool) error
	ThreadLocal() (uint64, error)
	DynamicSymbol(name string) (uint64, bool)
	ImportAddress(name string) (uint64, error)
	CreateGuestThread(arguments [8]uint64) (uint64, error)
	JoinGuestThread(arguments [8]uint64) (uint64, error)
}
