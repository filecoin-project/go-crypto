package crypto

import (
	"bytes"
	"crypto/rand"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// PrivateKeyBytes is the size of a serialized private key.
const PrivateKeyBytes = 32

// PublicKeyBytes is the size of a serialized public key.
const PublicKeyBytes = 65

// PublicKey returns the public key for this private key.
func PublicKey(sk []byte) []byte {
	priv := secp256k1.PrivKeyFromBytes(sk)
	pubkey := priv.PubKey()
	return pubkey.SerializeUncompressed()
}

// Sign signs the given message, which must be 32 bytes long.
func Sign(sk, msg []byte) ([]byte, error) {
	priv := secp256k1.PrivKeyFromBytes(sk)
	sig := ecdsa.SignCompact(priv, msg, false)
	return sig, nil
}

// Equals compares two private key for equality and returns true if they are the same.
func Equals(sk, other []byte) bool {
	return bytes.Equal(sk, other)
}

// Verify checks the given signature and returns true if it is valid.
func Verify(pk, msg, signature []byte) bool {
	pub, err := secp256k1.ParsePubKey(pk)
	if err != nil {
		return false
	}
	sig, err := ecdsa.ParseDERSignature(signature)
	if err != nil {
		return false
	}
	return sig.Verify(msg, pub)
}

// GenerateKeyFromSeed generates a new key from the given reader.
func GenerateKeyFromSeed(seed io.Reader) ([]byte, error) {
	priv, err := secp256k1.GeneratePrivateKeyFromRand(seed)
	if err != nil {
		return nil, err
	}
	return priv.Serialize(), nil
}

// GenerateKey creates a new key using secure randomness from crypto.rand.
func GenerateKey() ([]byte, error) {
	return GenerateKeyFromSeed(rand.Reader)
}

// EcRecover recovers the public key from a message, signature pair.
func EcRecover(msg, signature []byte) ([]byte, error) {
	pub, _, err := ecdsa.RecoverCompact(signature, msg)
	if err != nil {
		return nil, err
	}
	return pub.SerializeUncompressed(), nil
}
