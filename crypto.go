package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"io"

	secpEc "gitlab.com/yawning/secp256k1-voi/secec"
)

// PrivateKeyBytes is the size of a serialized private key.
const PrivateKeyBytes = 32

// PublicKeyBytes is the size of a serialized public key.
const PublicKeyBytes = 65

// PublicKey returns the public key for this private key.
func PublicKey(sk []byte) []byte {
	pk, err := secpEc.NewPrivateKey(sk)
	if err != nil {
		panic(err)
	}

	return pk.PublicKey().Bytes()
}

// Sign signs the given message, which must be 32 bytes long.
func Sign(sk, msg []byte) ([]byte, error) {
	pk, err := secpEc.NewPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	// Encoding is set to "EncodingCompactRecoverable" to ensure the signature is in [R | S | V] style.
	// The V (1byte) is the recovery bit and is not apart of the signature verification, rather prevents malleable signatures by inverting them.
	return pk.Sign(rand.Reader, msg, &secpEc.ECDSAOptions{Encoding: secpEc.EncodingCompactRecoverable, RejectMalleable: true, Hash: crypto.SHA256})
}

// Equals compares two private key for equality and returns true if they are the same.
func Equals(sk, other []byte) bool {
	return bytes.Equal(sk, other)
}

// Verify checks the given signature and returns true if it is valid.
func Verify(pk, msg, signature []byte) bool {
	pub, err := secpEc.NewPublicKey(pk)
	if err != nil {
		return false
	}

	ecsdaOpts := &secpEc.ECDSAOptions{Encoding: secpEc.EncodingCompact, RejectMalleable: true, Hash: crypto.SHA256}

	// Check if the signature is in [R | S | V] style.
	// if so, we change the Encoding to "EncodingCompactRecoverable"
	if len(signature) == 65 {
		// Normally you would drop the V (1byte) in [R | S | V] style signatures.
		// The V (1byte) is the recovery bit and is not apart of the signature verification.
		// EncodingCompactRecoverable expects the V to be included in the signature
		ecsdaOpts.Encoding = secpEc.EncodingCompactRecoverable
	}

	return pub.Verify(msg, signature, ecsdaOpts)
}

// GenerateKeyFromSeed generates a new key from the given reader.
// Deprecated: use GenerateKey instead - the given reader is no longer used.
func GenerateKeyFromSeed(io.Reader) ([]byte, error) {
	return GenerateKey()
}

// GenerateKey creates a new key using secure randomness from crypto.rand.
func GenerateKey() ([]byte, error) {
	key, err := secpEc.GenerateKey()
	if err != nil {
		return nil, err
	}

	return key.Bytes(), nil
}

// EcRecover recovers the public key from a message, signature pair.
func EcRecover(msg, signature []byte) ([]byte, error) {
	if len(signature) == 65 {
		// parse the compact signature into its (`r`,`s`) scalars and `v` recovery bit
		r, s, v, err := secpEc.ParseCompactRecoverableSignature(signature)
		if err != nil {
			return nil, err
		}

		pk, err := secpEc.RecoverPublicKey(msg, r, s, v)
		if err != nil {
			return nil, err
		}

		return pk.Bytes(), nil
	}

	// parse the compact signature into its (`r`,`s`) scalars (without `v` recovery bit)
	r, s, err := secpEc.ParseCompactSignature(signature)
	if err != nil {
		return nil, err
	}

	pk, err := secpEc.RecoverPublicKey(msg, r, s, byte(0))
	if err != nil {
		return nil, err
	}

	return pk.Bytes(), nil
}
