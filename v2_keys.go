package paseto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
)

// V2AsymmetricPublicKey V2 public public key
type V2AsymmetricPublicKey struct {
	material ed25519.PublicKey
}

// NewV2AsymmetricPublicKeyFromHex Construct a v2 public key from hex
func NewV2AsymmetricPublicKeyFromHex(hexEncoded string) (V2AsymmetricPublicKey, error) {
	publicKey, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey().Public(), err
	}

	if len(publicKey) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey().Public(), errors.New("Key incorrect length")
	}

	return V2AsymmetricPublicKey{publicKey}, nil
}

// ExportHex export a V2AsymmetricPublicKey to hex for storage
func (k V2AsymmetricPublicKey) ExportHex() string {
	return hex.EncodeToString(k.material)
}

// V2AsymmetricSecretKey V2 public private key
type V2AsymmetricSecretKey struct {
	material ed25519.PrivateKey
}

// Public returns the corresponding public key for a secret key
func (k V2AsymmetricSecretKey) Public() V2AsymmetricPublicKey {
	material, ok := k.material.Public().(ed25519.PublicKey)

	if !ok {
		panic("Wrong public key returned")
	}

	return V2AsymmetricPublicKey{material}
}

// ExportHex export a V2AsymmetricSecretKey to hex for storage
func (k V2AsymmetricSecretKey) ExportHex() string {
	return hex.EncodeToString(k.material)
}

// ExportSeedHex export a V2AsymmetricSecretKey's seed to hex for storage
func (k V2AsymmetricSecretKey) ExportSeedHex() string {
	return hex.EncodeToString(k.material.Seed())
}

// NewV2AsymmetricSecretKey generate a new secret key for use with asymmetric
// cryptography. Don't forget to export the public key for sharing, DO NOT share
// this secret key.
func NewV2AsymmetricSecretKey() V2AsymmetricSecretKey {
	_, privateKey, err := ed25519.GenerateKey(nil)

	if err != nil {
		panic("CSPRNG failure")
	}

	return V2AsymmetricSecretKey{privateKey}
}

// NewV2AsymmetricSecretKeyFromHex creates a secret key from hex
func NewV2AsymmetricSecretKeyFromHex(hexEncoded string) (V2AsymmetricSecretKey, error) {
	privateKey, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey(), err
	}

	if len(privateKey) != 64 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey(), errors.New("Key incorrect length")
	}

	return V2AsymmetricSecretKey{privateKey}, nil
}

// NewV2AsymmetricSecretKeyFromSeed creates a secret key from a seed (hex)
func NewV2AsymmetricSecretKeyFromSeed(hexEncoded string) (V2AsymmetricSecretKey, error) {
	seedBytes, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey(), err
	}

	if len(seedBytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey(), errors.New("Key incorrect length")
	}

	return V2AsymmetricSecretKey{ed25519.NewKeyFromSeed(seedBytes)}, nil
}

// V2SymmetricKey v2 local symmetric key
type V2SymmetricKey struct {
	material [32]byte
}

// NewV2SymmetricKey generates a new symmetric key for encryption
func NewV2SymmetricKey() V2SymmetricKey {
	var material [32]byte

	_, err := io.ReadFull(rand.Reader, material[:])

	if err != nil {
		panic("CSPRNG failure")
	}

	return V2SymmetricKey{material}
}

// ExportHex exports the key as hex for storage
func (k V2SymmetricKey) ExportHex() string {
	return hex.EncodeToString(k.material[:])
}

// V2SymmetricKeyFromHex constructs a key from hex
func V2SymmetricKeyFromHex(hexEncoded string) (V2SymmetricKey, error) {
	bytes, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2SymmetricKey(), err
	}

	if len(bytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2SymmetricKey(), errors.New("Key incorrect length")
	}

	var material [32]byte

	copy(material[:], bytes)

	return V2SymmetricKey{material}, nil
}
