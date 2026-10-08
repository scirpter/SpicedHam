package native

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"snapnative/internal/account"
)

// Authentication and Fidelius initialization are distinct original operations.
// L8e/uK0.c can preserve real issued authentication while clearing failed local
// Fidelius initialization. Missing or mismatched server binding never authorizes
// persisting the submitted tentative keys as an initialized identity.
type PasswordLoginResult struct {
	Session       *account.NativeSession
	FideliusError error
}

// xP1.field5 tj8: server IWEK field1, full public-key HMAC bytes field2.
// Original rK0/D51/wX6 first resolves an existing identity by its binding; a new
// candidate uses the RETURNED IWEK and retained SPKI/private/version. QVl.b and
// r98.r compare Base64 of these same full HMAC bytes, not SHA(publicKey).
func finalizeFidelius(success []byte, pending account.FideliusKeys, version int64, previous *account.NativeSession) (account.FideliusKeys, int64, error) {
	initialization, _, err := messageField(success, 5)
	if err != nil {
		return account.FideliusKeys{}, 0, err
	}
	var iwek, binding []byte
	d := decoder{rest: initialization}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		switch entry.number {
		case 1:
			iwek, err = entry.asBytes()
		case 2:
			binding, err = entry.asBytes()
		}
		if err != nil {
			return account.FideliusKeys{}, 0, err
		}
	}
	if d.err != nil {
		return account.FideliusKeys{}, 0, d.err
	}
	if len(iwek) == 0 {
		return account.FideliusKeys{}, 0, errors.New("Fidelius initialization: null_iwek")
	}
	if len(binding) == 0 {
		return account.FideliusKeys{}, 0, errors.New("Fidelius initialization: null_hashed_out_beta")
	}
	candidate, candidateVersion := pending, version
	if previous != nil && len(previous.Fidelius.IWEK) != 0 && len(previous.Fidelius.PublicKeySPKI) != 0 && fideliusBindingMatches(iwek, previous.Fidelius.PublicKeySPKI, binding) {
		candidate, candidateVersion = previous.Fidelius, previous.FideliusVersion
	} else if !fideliusBindingMatches(iwek, pending.PublicKeySPKI, binding) {
		return account.FideliusKeys{}, 0, errors.New("Fidelius initialization: local_mismatch")
	}
	if candidateVersion != 9 && candidateVersion != 10 {
		return account.FideliusKeys{}, 0, errors.New("Fidelius initialization has no genuine supported identity version")
	}
	if err := validateFideliusPair(candidate); err != nil {
		return account.FideliusKeys{}, 0, err
	}
	// Own finalized storage independently of the response, pending submission,
	// and prior session. Their owners may clear or replace those buffers.
	return account.FideliusKeys{
		IWEK:            bytes.Clone(iwek),
		PrivateKeyPKCS8: bytes.Clone(candidate.PrivateKeyPKCS8),
		PublicKeySPKI:   bytes.Clone(candidate.PublicKeySPKI),
	}, candidateVersion, nil
}

func fideliusBindingMatches(iwek, public, expected []byte) bool {
	mac := hmac.New(sha256.New, iwek)
	mac.Write(public)
	return hmac.Equal(mac.Sum(nil), expected)
}

func validateFideliusPair(keys account.FideliusKeys) error {
	public, err := x509.ParsePKIXPublicKey(keys.PublicKeySPKI)
	if err != nil {
		return fmt.Errorf("Fidelius finalized SPKI: %w", err)
	}
	ecPublic, ok := public.(*ecdsa.PublicKey)
	if !ok || ecPublic.Curve != elliptic.P256() {
		return errors.New("Fidelius finalized public key is not P-256")
	}
	private, err := x509.ParsePKCS8PrivateKey(keys.PrivateKeyPKCS8)
	if err != nil {
		return fmt.Errorf("Fidelius finalized private key: %w", err)
	}
	switch key := private.(type) {
	case *ecdsa.PrivateKey:
		if key.PublicKey.Equal(ecPublic) {
			return nil
		}
	case *ecdh.PrivateKey:
		converted, err := ecPublic.ECDH()
		if err == nil && key.PublicKey().Equal(converted) {
			return nil
		}
	}
	return errors.New("Fidelius finalized private/public keys do not match")
}
