package crypto

import (
	"crypto/ed25519"
	"errors"
)

// Sign produces an ed25519 signature over data.
// Signing ≠ hashing: a hash proves data integrity (unchanged),
// but a signature proves authenticity.
// ed25519 signs the raw bytes; callers should pass a hash for efficiency.
func Sign(data []byte, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, data)
}

// Verify checks that sig was produced by the holder of pub over data.
// Returns an error on any mismatch so callers can reject explicitly.
func Verify(data, sig []byte, pub ed25519.PublicKey) error {
	if !ed25519.Verify(pub, data, sig) {
		return errors.New("signature verification failed: invalid or mismatched key")
	}
	return nil
}

// MultiSig holds the two mandatory signatures for an anchor.
// Requiring BOTH prevents single-point trust: even if one agent is
// compromised, the anchor cannot be forged without the second key.
type MultiSig struct {
	ExecutionSig  []byte
	ValidationSig []byte
}

// VerifyBoth verifies both signatures against data.
// Returns an error if either is missing or invalid.
func (m *MultiSig) VerifyBoth(data []byte, execPub, valPub ed25519.PublicKey) error {
	if len(m.ExecutionSig) == 0 {
		return errors.New("missing execution signature")
	}
	if len(m.ValidationSig) == 0 {
		return errors.New("missing validation signature")
	}
	if err := Verify(data, m.ExecutionSig, execPub); err != nil {
		return errors.New("execution " + err.Error())
	}
	if err := Verify(data, m.ValidationSig, valPub); err != nil {
		return errors.New("validation " + err.Error())
	}
	return nil
}
