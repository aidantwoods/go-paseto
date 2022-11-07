package paseto

import (
	"crypto/ed25519"
	"encoding/hex"

	"aidanwoods.dev/go-paseto/internal/hashing"
	"aidanwoods.dev/go-paseto/internal/random"
)

// V4AsymmetricPublicKey v4 public public key
type V4AsymmetricPublicKey struct {
	material ed25519.PublicKey
}

// NewV4AsymmetricPublicKeyFromHex Construct a v4 public key from hex
func NewV4AsymmetricPublicKeyFromHex(hexEncoded string) (V4AsymmetricPublicKey, error) {
	publicKey, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey().Public(), err
	}

	return NewV4AsymmetricPublicKeyFromBytes(publicKey)
}

// NewV4AsymmetricPublicKeyFromBytes Construct a v4 public key from bytes
func NewV4AsymmetricPublicKeyFromBytes(publicKey []byte) (V4AsymmetricPublicKey, error) {
	if len(publicKey) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey().Public(), errorKeyLength(32, len(publicKey))
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
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey(), err
	}

	return NewV4AsymmetricSecretKeyFromBytes(privateKey)
}

func isEd25519KeyPairMalformed(privateKey []byte) bool {
	seed := privateKey[:32]

	pubKeyFromGiven := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	pubKeyFromSeed := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	return !pubKeyFromGiven.Equal(pubKeyFromSeed)
}

// NewV4AsymmetricSecretKeyFromBytes creates a secret key from bytes
func NewV4AsymmetricSecretKeyFromBytes(privateKey []byte) (V4AsymmetricSecretKey, error) {
	if len(privateKey) != 64 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey(), errorKeyLength(64, len(privateKey))
	}

	if isEd25519KeyPairMalformed(privateKey) {
		// even though we return error, return a random key here rather than
		// a nil key
		// This should catch poorly formed private keys (ones that do not embed
		// a public key which corresponds to their private portion)
		return NewV4AsymmetricSecretKey(), errorKeyInvalid
	}

	return V4AsymmetricSecretKey{privateKey}, nil
}

// NewV4AsymmetricSecretKeyFromSeed creates a secret key from a seed (hex)
func NewV4AsymmetricSecretKeyFromSeed(hexEncoded string) (V4AsymmetricSecretKey, error) {
	seedBytes, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey(), err
	}

	if len(seedBytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey(), errorSeedLength(32, len(seedBytes))
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
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4SymmetricKey(), err
	}

	return V4SymmetricKeyFromBytes(bytes)
}

// V4SymmetricKeyFromBytes constructs a key from bytes
func V4SymmetricKeyFromBytes(bytes []byte) (V4SymmetricKey, error) {
	if len(bytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4SymmetricKey(), errorKeyLength(32, len(bytes))
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
