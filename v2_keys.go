package paseto

import (
	"crypto/ed25519"
	"encoding/hex"

	"aidanwoods.dev/go-paseto/v2/internal/encoding"
	"aidanwoods.dev/go-paseto/v2/internal/random"
	t "aidanwoods.dev/go-result"
)

// V2AsymmetricPublicKey V2 public public key
type V2AsymmetricPublicKey struct {
	material ed25519.PublicKey
}

// NewV2AsymmetricPublicKeyFromHex Construct a v2 public key from hex
func NewV2AsymmetricPublicKeyFromHex(hexEncoded string) (V2AsymmetricPublicKey, error) {
	var publicKey []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&publicKey); err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey().Public(), err
	}

	return NewV2AsymmetricPublicKeyFromBytes(publicKey)
}

// NewV2AsymmetricPublicKeyFromBytes Construct a v2 public key from bytes
func NewV2AsymmetricPublicKeyFromBytes(publicKey []byte) (V2AsymmetricPublicKey, error) {
	if len(publicKey) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey().Public(), errorKeyLength(32, len(publicKey))
	}

	return V2AsymmetricPublicKey{publicKey}, nil
}

// NewV2AsymmetricPublicKeyFromEd25519 Construct a v2 public key from a standard Go object
func NewV2AsymmetricPublicKeyFromEd25519(publicKey ed25519.PublicKey) (V2AsymmetricPublicKey, error) {
	return NewV2AsymmetricPublicKeyFromBytes([]byte(publicKey))
}

// ExportHex export a V2AsymmetricPublicKey to hex for storage
func (k V2AsymmetricPublicKey) ExportHex() string {
	return encoding.HexEncode(k.ExportBytes())
}

// ExportBytes export a V2AsymmetricPublicKey to raw byte array
func (k V2AsymmetricPublicKey) ExportBytes() []byte {
	return k.material
}

// V2AsymmetricSecretKey V2 public private key
type V2AsymmetricSecretKey struct {
	material ed25519.PrivateKey
}

// Public returns the corresponding public key for a secret key
func (k V2AsymmetricSecretKey) Public() V2AsymmetricPublicKey {
	return V2AsymmetricPublicKey{
		material: t.Cast[ed25519.PublicKey](k.material.Public()).
			Expect("wrong public key returned"),
	}
}

// ExportHex export a V2AsymmetricSecretKey to hex for storage
func (k V2AsymmetricSecretKey) ExportHex() string {
	return encoding.HexEncode(k.ExportBytes())
}

// ExportBytes export a V2AsymmetricSecretKey to raw byte array
func (k V2AsymmetricSecretKey) ExportBytes() []byte {
	return k.material
}

// ExportSeedHex export a V2AsymmetricSecretKey's seed to hex for storage
func (k V2AsymmetricSecretKey) ExportSeedHex() string {
	return encoding.HexEncode(k.material.Seed())
}

// NewV2AsymmetricSecretKey generate a new secret key for use with asymmetric
// cryptography. Don't forget to export the public key for sharing, DO NOT share
// this secret key.
func NewV2AsymmetricSecretKey() V2AsymmetricSecretKey {
	return V2AsymmetricSecretKey{
		material: t.NewTupleResult(ed25519.GenerateKey(nil)).
			Expect("CSPRNG should not fail").
			Second,
	}
}

// NewV2AsymmetricSecretKeyFromHex creates a secret key from hex
func NewV2AsymmetricSecretKeyFromHex(hexEncoded string) (V2AsymmetricSecretKey, error) {
	var privateKey []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&privateKey); err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey(), err
	}

	return NewV2AsymmetricSecretKeyFromBytes(privateKey)
}

// NewV2AsymmetricSecretKeyFromBytes creates a secret key from bytes
func NewV2AsymmetricSecretKeyFromBytes(privateKey []byte) (V2AsymmetricSecretKey, error) {
	if len(privateKey) != 64 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey(), errorKeyLength(64, len(privateKey))
	}

	if isEd25519KeyPairMalformed(privateKey) {
		// even though we return error, return a random key here rather than
		// a nil key
		// This should catch poorly formed private keys (ones that do not embed
		// a public key which corresponds to their private portion)
		return NewV2AsymmetricSecretKey(), errorKeyInvalid
	}

	return V2AsymmetricSecretKey{privateKey}, nil
}

// NewV2AsymmetricSecretKeyFromEd25519 creates a secret key from a standard Go object
func NewV2AsymmetricSecretKeyFromEd25519(privateKey ed25519.PrivateKey) (V2AsymmetricSecretKey, error) {
	return NewV2AsymmetricSecretKeyFromBytes([]byte(privateKey))
}

// NewV2AsymmetricSecretKeyFromSeed creates a secret key from a seed (hex)
func NewV2AsymmetricSecretKeyFromSeed(hexEncoded string) (V2AsymmetricSecretKey, error) {
	var seedBytes []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&seedBytes); err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey(), err
	}

	if len(seedBytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2AsymmetricSecretKey(), errorSeedLength(32, len(seedBytes))
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
	random.FillBytes(material[:])

	return V2SymmetricKey{material}
}

// ExportHex exports the key as hex for storage
func (k V2SymmetricKey) ExportHex() string {
	return hex.EncodeToString(k.ExportBytes())
}

// ExportBytes exports the key as raw bytes
func (k V2SymmetricKey) ExportBytes() []byte {
	return k.material[:]
}

// V2SymmetricKeyFromHex constructs a key from hex
func V2SymmetricKeyFromHex(hexEncoded string) (V2SymmetricKey, error) {
	var bytes []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&bytes); err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2SymmetricKey(), err
	}

	return V2SymmetricKeyFromBytes(bytes)
}

// V2SymmetricKeyFromBytes constructs a key from bytes
func V2SymmetricKeyFromBytes(bytes []byte) (V2SymmetricKey, error) {
	if len(bytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV2SymmetricKey(), errorKeyLength(32, len(bytes))
	}

	var material [32]byte
	copy(material[:], bytes)

	return V2SymmetricKey{material}, nil
}
