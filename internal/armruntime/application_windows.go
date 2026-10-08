//go:build windows && amd64

package armruntime

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"snapnative/internal/account"
)

// HostApplicationConfig supplies a caller-verified, account-owned Windows scope.
// Paths name actual host storage, the signed source APK and the verified native
// deployment; PackageName comes from that APK, not an Android installation.
// Open snapshots this value once and never replaces a live account's scope.
type HostApplicationConfig struct {
	DataDirectory   string
	ArchivePath     string
	PackageName     string
	NativeDirectory string
}

// The original plain Application is attached only after the real host ports and
// owner-thread main Looper are ready. This does not run Mushroom/ActivityThread
// startup; the scoped collector's token reader is initialized separately.
func (j *JVM) attachApplication(scope HostApplicationConfig) error {
	if j.application != 0 || j.appBootstrap != 0 {
		return errors.New("genuine JVM already owns a Windows Application scope")
	}
	if j.mainQueue == 0 {
		return errors.New("Windows Application requires the original owner-thread main Looper")
	}
	bootstrap, err := j.Class("snapnative/host/WindowsApplicationBootstrap")
	if err != nil {
		return err
	}
	defer j.Call(23, false, bootstrap)
	closeMethod, err := j.Method(bootstrap, "close", "(Landroid/app/Application;)V", true)
	if err != nil {
		return err
	}
	attachMethod, err := j.Method(bootstrap, "attach", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/app/Application;", true)
	if err != nil {
		return err
	}
	globalBootstrap, err := j.Call(21, false, bootstrap)
	if globalBootstrap != 0 {
		// Close owns this class reference even if a later attach/retain fails.
		j.appBootstrap, j.closeApp = globalBootstrap, closeMethod
	}
	if err != nil {
		return err
	}
	if err := j.requireResult(globalBootstrap, "retain Windows Application bootstrap"); err != nil {
		return err
	}
	values := [4]string{scope.DataDirectory, scope.ArchivePath, scope.PackageName, scope.NativeDirectory}
	var arguments [4]uint64
	for index, value := range values {
		text := jniModifiedUTF8(value)
		object, err := j.Call(167, false, uintptr(unsafe.Pointer(unsafe.SliceData(text))))
		runtime.KeepAlive(text)
		if object != 0 {
			defer j.Call(23, false, object)
		}
		if err != nil {
			return err
		}
		if err := j.requireResult(object, "allocate Windows Application scope string"); err != nil {
			return err
		}
		arguments[index] = uint64(object)
	}
	application, err := j.Call(116, false, globalBootstrap, attachMethod, uintptr(unsafe.Pointer(&arguments[0])))
	runtime.KeepAlive(&arguments)
	if application != 0 {
		defer j.Call(23, false, application)
	}
	if err == nil {
		err = j.requireResult(application, "WindowsApplicationBootstrap.attach")
	}
	if err != nil {
		if application != 0 {
			err = errors.Join(err, j.closeApplicationReference(application))
		}
		return err
	}
	global, err := j.Call(21, false, application)
	if global != 0 {
		j.application = global
	}
	if err == nil {
		err = j.requireResult(global, "retain original attached Application")
	}
	if err != nil && global == 0 {
		// Attachment really completed, but retaining its owner did not. Dispose
		// the still-live local owner without discarding the original throwable.
		err = errors.Join(err, j.closeApplicationReference(application))
	}
	return err
}

// newAccumulator creates the original Aeh. Account-free native-smoke has no
// file owner; an actual account instead binds the original token reader to its
// immutable Windows Application scope, never an Android device/issuer profile.
func (j *JVM) newAccumulator() (uintptr, error) {
	className, methodName, signature := "Aeh", "<init>", "(LAVa;)V"
	index, static := uint(30), false
	arguments := [1]uint64{0}
	if j.application != 0 {
		className, methodName, signature = "WindowsAccumulatorBootstrap", "create", "(Landroid/app/Application;)LAeh;"
		index, static = 116, true
		arguments[0] = uint64(j.application)
	}
	class, err := j.Class(className)
	if err != nil {
		return 0, err
	}
	defer j.Call(23, false, class)
	method, err := j.Method(class, methodName, signature, static)
	if err != nil {
		return 0, err
	}
	value, err := j.Call(index, false, class, method, uintptr(unsafe.Pointer(&arguments[0])))
	runtime.KeepAlive(&arguments)
	return value, err
}

// AdoptDeviceToken binds an already issued token to this account's original
// EEd. Like ead.case9, the first non-null memo wins; callers persist the actual
// retained result in their account's protected state before reporting success.
// It supplies no handset identity, vendor attestation or anonymous token.
func (r *Runtime) AdoptDeviceToken(ctx context.Context, token account.DeviceToken) (account.DeviceToken, error) {
	if err := ctx.Err(); err != nil {
		return account.DeviceToken{}, err
	}
	r.gate.Lock()
	defer r.gate.Unlock()
	if r.closed || r.jvm == nil || r.jvm.application == 0 {
		return account.DeviceToken{}, errors.New("SDK device token requires a live account-owned Application")
	}
	j := r.jvm
	class, err := j.Class("WindowsAccumulatorBootstrap")
	if err != nil {
		return account.DeviceToken{}, err
	}
	defer j.Call(23, false, class)
	method, err := j.Method(class, "adoptDeviceToken", "(Landroid/app/Application;Ljava/lang/String;Ljava/lang/String;)LPU6;", true)
	if err != nil {
		return account.DeviceToken{}, err
	}
	arguments := [3]uint64{uint64(j.application)}
	for index, value := range [2]string{token.ID, token.Value} {
		text := jniModifiedUTF8(value)
		object, err := j.Call(167, false, uintptr(unsafe.Pointer(unsafe.SliceData(text))))
		runtime.KeepAlive(text)
		if object != 0 {
			defer j.Call(23, false, object)
		}
		if err != nil {
			return account.DeviceToken{}, err
		}
		if err := j.requireResult(object, "allocate issued SDK token string"); err != nil {
			return account.DeviceToken{}, err
		}
		arguments[index+1] = uint64(object)
	}
	object, err := j.Call(116, false, class, method, uintptr(unsafe.Pointer(&arguments[0])))
	runtime.KeepAlive(&arguments)
	if object != 0 {
		defer j.Call(23, false, object)
	}
	if err != nil {
		return account.DeviceToken{}, err
	}
	if err := j.requireResult(object, "adopt original SDK token"); err != nil {
		return account.DeviceToken{}, err
	}
	tokenClass, err := j.Class("PU6")
	if err != nil {
		return account.DeviceToken{}, err
	}
	defer j.Call(23, false, tokenClass)
	var retained account.DeviceToken
	for index, getter := range [2]string{"a", "b"} {
		method, err := j.Method(tokenClass, getter, "()Ljava/lang/String;", false)
		if err != nil {
			return account.DeviceToken{}, err
		}
		value, err := j.Call(36, false, object, method, 0)
		if value != 0 {
			defer j.Call(23, false, value)
		}
		if err != nil {
			return account.DeviceToken{}, err
		}
		if err := j.requireResult(value, "read retained original SDK token"); err != nil {
			return account.DeviceToken{}, err
		}
		text, err := j.stringValue(value)
		if err != nil {
			return account.DeviceToken{}, err
		}
		if index == 0 {
			retained.ID = text
		} else {
			retained.Value = text
		}
	}
	return retained, nil
}

// Borrow genuine UTF-16 characters only until ReleaseStringChars. Stream into
// the final Go string rather than allocate an intermediate rune/slice copy.
func (j *JVM) stringValue(object uintptr) (string, error) {
	length, err := j.Call(164, false, object)
	if err != nil {
		return "", err
	}
	if pending, err := j.Exception(); err != nil || pending {
		return "", errors.Join(err, errors.New("read original Java string length failed"))
	}
	if length == 0 {
		return "", nil
	}
	pointer, err := j.Call(165, false, object, 0)
	if err != nil {
		return "", err
	}
	if err := j.requireResult(pointer, "borrow original Java string"); err != nil {
		return "", err
	}
	defer j.Call(166, false, object, pointer)
	characters := unsafe.Slice((*uint16)(unsafe.Pointer(pointer)), int(length))
	var text strings.Builder
	text.Grow(3 * len(characters))
	for index := 0; index < len(characters); index++ {
		value := rune(characters[index])
		if utf16.IsSurrogate(value) {
			value = utf8.RuneError
			if index+1 < len(characters) {
				value = utf16.DecodeRune(rune(characters[index]), rune(characters[index+1]))
				if value != utf8.RuneError {
					index++
				}
			}
		}
		text.WriteRune(value)
	}
	return text.String(), nil
}

// Like disposeMainQueue, cleanup temporarily clears only a saved real Throwable,
// reports any cleanup exception, then restores the exact original Throwable.
// Close exclusively owns the worker; these raw calls still run on its C thread.
func (j *JVM) closeApplicationReference(application uintptr) (failure error) {
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
				failure = errors.Join(failure, errors.New("restore genuine pending throwable after Application disposal failed"))
			}
			_, err = j.callWorker(23, false, saved)
			failure = errors.Join(failure, err)
		}()
	}
	arguments := [1]uint64{uint64(application)}
	_, failure = j.callWorker(143, false, j.appBootstrap, j.closeApp, uintptr(unsafe.Pointer(&arguments[0])))
	runtime.KeepAlive(&arguments)
	pending, err := j.callWorker(228, false)
	failure = errors.Join(failure, err)
	if uint8(pending) != 0 {
		failure = errors.Join(failure, errors.New("WindowsApplicationBootstrap.close raised a genuine pending Java exception"))
	}
	return failure
}

func (j *JVM) disposeApplication() error {
	var failure error
	if j.application != 0 {
		failure = j.closeApplicationReference(j.application)
		_, err := j.callWorker(22, false, j.application)
		failure = errors.Join(failure, err)
	}
	if j.appBootstrap != 0 {
		_, err := j.callWorker(22, false, j.appBootstrap)
		failure = errors.Join(failure, err)
	}
	j.application, j.appBootstrap, j.closeApp = 0, 0, 0
	return failure
}
