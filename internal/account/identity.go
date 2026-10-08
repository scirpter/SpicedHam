package account

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// Each isolated account is a distinct software-port logical Android user. This
// ports AOSP Android 13 SettingsProvider's persisted SSAID user-key semantics;
// it does not identify an existing handset or attest to hardware/Android state.
// Accounts sharing a real Android user and signer would instead share its SSAID.
func (installation *Installation) ensureSSAIDUserKey() (bool, error) {
	if installation.SSAIDUserKey == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return false, fmt.Errorf("generate software-installation SSAID user key: %w", err)
		}
		installation.SSAIDUserKey = key
		return true, nil
	}
	// AOSP accepts surviving legacy 16-byte keys; fresh keys are always 32 bytes.
	if len(installation.SSAIDUserKey) != 16 && len(installation.SSAIDUserKey) != 32 {
		return false, errors.New("persisted SSAID user key must contain 16 or 32 bytes")
	}
	return false, nil
}

// ensureCloudAccountID preserves the original app-scoped Janus identifier
// across processes and login attempts. It is not a device or integrity claim.
func (installation *Installation) ensureCloudAccountID() (bool, error) {
	if installation.CloudAccountID != "" {
		return false, nil
	}
	id, err := FreshUUID()
	if err != nil {
		return false, fmt.Errorf("generate cloud account ID: %w", err)
	}
	installation.CloudAccountID = id
	return true, nil
}

// AndroidIdentifier returns canonical raw SSAID bytes, not Fidelius's typed
// nine-byte identity. signingCertificatesDER must be the full original APK
// GET_SIGNATURES certificates, in their original array order: neither public
// keys nor certificate fingerprints are certificates. DER parsing validates
// their encoding; it does not verify APK signatures or publisher authenticity.
//
// AOSP Android 13 SettingsProvider.generateSsaidLocked hashes each certificate's
// BE32 byte length followed by its full DER with the independently persisted
// logical-user key, then exposes the first eight HMAC-SHA256 bytes as hex text.
// This software-port identity is independent of IWEK, credentials, sessions,
// ClientID rotation and hardware provenance.
func (installation Installation) AndroidIdentifier(signingCertificatesDER [][]byte) ([8]byte, error) {
	var identifier [8]byte
	if len(installation.SSAIDUserKey) != 16 && len(installation.SSAIDUserKey) != 32 {
		return identifier, errors.New("Android identifier requires a persisted SSAID user key")
	}
	if len(signingCertificatesDER) == 0 {
		return identifier, errors.New("Android identifier requires original APK signing certificates")
	}
	mac := hmac.New(sha256.New, installation.SSAIDUserKey)
	var length [4]byte
	for index, der := range signingCertificatesDER {
		if uint64(len(der)) > 0xffffffff {
			return identifier, fmt.Errorf("APK signing certificate %d exceeds the SSAID length encoding", index)
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			return identifier, fmt.Errorf("parse APK signing certificate %d DER: %w", index, err)
		}
		binary.BigEndian.PutUint32(length[:], uint32(len(der)))
		_, _ = mac.Write(length[:])
		_, _ = mac.Write(der)
	}
	var digest [sha256.Size]byte
	mac.Sum(digest[:0])
	copy(identifier[:], digest[:len(identifier)])
	return identifier, nil
}
