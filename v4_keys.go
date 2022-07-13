package paseto

import (
	"crypto/ed25519"
	"encoding/hex"

	"aidanwoods.dev/go-paseto/internal/hashing"
	"aidanwoods.dev/go-paseto/internal/random"
	"github.com/pkg/errors"
)

// V4AsymmetricPublicKey v4 public public key
type V4AsymmetricPublicKey struct {
	material ed25519.PublicKey
}

// NewV4AsymmetricPublicKeyFromHex Construct a v4 public key from hex
func NewV4AsymmetricPublicKeyFromHex(hexEncoded string) (V4AsymmetricPublicKey, error) {
	publicKey, err := hex.DecodeString(hexEncoded)

	if err != nil {

		return V4AsymmetricPublicKey{}, err
	}

	return NewV4AsymmetricPublicKeyFromBytes(publicKey)
}

// NewV4AsymmetricPublicKeyFromBytes Construct a v4 public key from bytes
func NewV4AsymmetricPublicKeyFromBytes(publicKey []byte) (V4AsymmetricPublicKey, error) {
	if len(publicKey) != 32 {

		return V4AsymmetricPublicKey{}, errors.New("Key incorrect length")
	}

	return V4AsymmetricPublicKey{publicKey}, nil
}

// ExportHex export a V4AsymmetricPublicKey to hex for storage
func (k V4AsymmetricPublicKey) ExportHex() string {
	return hex.EncodeToString(k.ExportBytes())
}

// ExportBytes export a V4AsymmetricPublicKey to raw byte array
func (k V4AsymmetricPublicKey) ExportBytes() []byte {
	return k.material
}

// V4AsymmetricSecretKey v4 public private key
type V4AsymmetricSecretKey struct {
	material ed25519.PrivateKey
}

// Public returns the corresponding public key for a secret key
func (k V4AsymmetricSecretKey) Public() V4AsymmetricPublicKey {
	material, ok := k.material.Public().(ed25519.PublicKey)

	if !ok {
		panic("Wrong public key returned")
	}

	return V4AsymmetricPublicKey{material}
}

// ExportHex export a V4AsymmetricSecretKey to hex for storage
func (k V4AsymmetricSecretKey) ExportHex() string {
	return hex.EncodeToString(k.ExportBytes())
}

// ExportBytes export a V4AsymmetricSecretKey to raw byte array
func (k V4AsymmetricSecretKey) ExportBytes() []byte {
	return k.material
}

// ExportSeedHex export a V4AsymmetricSecretKey's seed to hex for storage
func (k V4AsymmetricSecretKey) ExportSeedHex() string {
	return hex.EncodeToString(k.material.Seed())
}

// NewV4AsymmetricSecretKey generate a new secret key for use with asymmetric
// cryptography. Don't forget to export the public key for sharing, DO NOT share
// this secret key.
func NewV4AsymmetricSecretKey() V4AsymmetricSecretKey {
	_, privateKey, err := ed25519.GenerateKey(nil)

	if err != nil {
		panic("CSPRNG failure")
	}

	return V4AsymmetricSecretKey{privateKey}
}

// NewV4AsymmetricSecretKeyFromHex creates a secret key from hex
func NewV4AsymmetricSecretKeyFromHex(hexEncoded string) (V4AsymmetricSecretKey, error) {
	privateKey, err := hex.DecodeString(hexEncoded)

	if err != nil {

		return V4AsymmetricSecretKey{}, err
	}

	return NewV4AsymmetricSecretKeyFromBytes(privateKey)
}

// NewV4AsymmetricSecretKeyFromBytes creates a secret key from bytes
func NewV4AsymmetricSecretKeyFromBytes(privateKey []byte) (V4AsymmetricSecretKey, error) {
	if len(privateKey) != 64 {

		return V4AsymmetricSecretKey{}, errors.New("Key incorrect length")
	}

	return V4AsymmetricSecretKey{privateKey}, nil
}

// NewV4AsymmetricSecretKeyFromSeed creates a secret key from a seed (hex)
func NewV4AsymmetricSecretKeyFromSeed(hexEncoded string) (V4AsymmetricSecretKey, error) {
	seedBytes, err := hex.DecodeString(hexEncoded)

	if err != nil {

		return V4AsymmetricSecretKey{}, err
	}

	if len(seedBytes) != 32 {

		return V4AsymmetricSecretKey{}, errors.New("Key incorrect length")
	}

	return V4AsymmetricSecretKey{ed25519.NewKeyFromSeed(seedBytes)}, nil
}

// V4SymmetricKey v4 local symmetric key
type V4SymmetricKey struct {
	material [32]byte
}

// NewV4SymmetricKey generates a new symmetric key for encryption
func NewV4SymmetricKey() V4SymmetricKey {
	var material [32]byte
	random.FillBytes(material[:])

	return V4SymmetricKey{material}
}

// ExportHex exports the key as hex for storage
func (k V4SymmetricKey) ExportHex() string {
	return hex.EncodeToString(k.ExportBytes())
}

// ExportBytes exports the key as raw byte array
func (k V4SymmetricKey) ExportBytes() []byte {
	return k.material[:]
}

// V4SymmetricKeyFromHex constructs a key from hex
func V4SymmetricKeyFromHex(hexEncoded string) (V4SymmetricKey, error) {
	bytes, err := hex.DecodeString(hexEncoded)

	if err != nil {

		return V4SymmetricKey{}, err
	}

	return V4SymmetricKeyFromBytes(bytes)
}

// V4SymmetricKeyFromBytes constructs a key from bytes
func V4SymmetricKeyFromBytes(bytes []byte) (V4SymmetricKey, error) {
	if len(bytes) != 32 {

		return V4SymmetricKey{}, errors.New("Key incorrect length")
	}

	var material [32]byte

	copy(material[:], bytes)

	return V4SymmetricKey{material}, nil
}

func (k V4SymmetricKey) split(nonce [32]byte) (encKey [32]byte, authkey [32]byte, nonce2 [24]byte) {
	var tmp [56]byte
	hashing.GenericHash(
		append([]byte("paseto-encryption-key"), nonce[:]...),
		tmp[:],
		k.material[:],
	)

	copy(encKey[:], tmp[0:32])
	copy(nonce2[:], tmp[32:56])

	hashing.GenericHash(
		append([]byte("paseto-auth-key-for-aead"), nonce[:]...),
		authkey[:],
		k.material[:],
	)

	return encKey, authkey, nonce2
}
