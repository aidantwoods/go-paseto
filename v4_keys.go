package paseto

import (
	"crypto/ed25519"

	"aidanwoods.dev/go-paseto/v2/internal/encoding"
	"aidanwoods.dev/go-paseto/v2/internal/hashing"
	"aidanwoods.dev/go-paseto/v2/internal/random"
	t "aidanwoods.dev/go-result"
)

// V4AsymmetricPublicKey v4 public public key
type V4AsymmetricPublicKey struct {
	material ed25519.PublicKey
}

// NewV4AsymmetricPublicKeyFromHex Construct a v4 public key from hex
func NewV4AsymmetricPublicKeyFromHex(hexEncoded string) (V4AsymmetricPublicKey, error) {
	var publicKey []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&publicKey); err != nil {
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

// NewV4AsymmetricPublicKeyFromEd25519 Construct a v2 public key from a standard Go object
func NewV4AsymmetricPublicKeyFromEd25519(publicKey ed25519.PublicKey) (V4AsymmetricPublicKey, error) {
	return NewV4AsymmetricPublicKeyFromBytes([]byte(publicKey))
}

// ExportHex export a V4AsymmetricPublicKey to hex for storage
func (k V4AsymmetricPublicKey) ExportHex() string {
	return encoding.HexEncode(k.ExportBytes())
}

// ExportBytes export a V4AsymmetricPublicKey to raw byte array
func (k V4AsymmetricPublicKey) ExportBytes() []byte {
	return k.material
}

func (k *V4AsymmetricPublicKey) getVersion() KeyVersion {
	return KeyVersionV4
}
func (k *V4AsymmetricPublicKey) getPurpose() keyPurpose {
	return keyPurposePublic
}

// V4AsymmetricSecretKey v4 public private key
type V4AsymmetricSecretKey struct {
	material ed25519.PrivateKey
}

// Public returns the corresponding public key for a secret key
func (k V4AsymmetricSecretKey) Public() V4AsymmetricPublicKey {
	return V4AsymmetricPublicKey{
		material: t.Cast[ed25519.PublicKey](k.material.Public()).
			Expect("should produce ed25519 public key"),
	}
}

// ExportHex export a V4AsymmetricSecretKey to hex for storage
func (k V4AsymmetricSecretKey) ExportHex() string {
	return encoding.HexEncode(k.ExportBytes())
}

// ExportBytes export a V4AsymmetricSecretKey to raw byte array
func (k V4AsymmetricSecretKey) ExportBytes() []byte {
	return k.material
}

// ExportSeedHex export a V4AsymmetricSecretKey's seed to hex for storage
func (k V4AsymmetricSecretKey) ExportSeedHex() string {
	return encoding.HexEncode(k.material.Seed())
}

// NewV4AsymmetricSecretKey generate a new secret key for use with asymmetric
// cryptography. Don't forget to export the public key for sharing, DO NOT share
// this secret key.
func NewV4AsymmetricSecretKey() V4AsymmetricSecretKey {
	return V4AsymmetricSecretKey{
		material: t.NewTupleResult(ed25519.GenerateKey(nil)).
			Expect("CSPRNG should succeed").
			Second,
	}
}

// NewV4AsymmetricSecretKeyFromHex creates a secret key from hex
func NewV4AsymmetricSecretKeyFromHex(hexEncoded string) (V4AsymmetricSecretKey, error) {
	var privateKey []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&privateKey); err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey(), err
	}

	return NewV4AsymmetricSecretKeyFromBytes(privateKey)
}

func isEd25519KeyPairMalformed(privateKey []byte) bool {
	seed := privateKey[:32]

	pubKeyFromGiven := t.Cast[ed25519.PublicKey](ed25519.PrivateKey(privateKey).Public()).
		Expect("should return ed25519 public key")
	pubKeyFromSeed := t.Cast[ed25519.PublicKey](ed25519.NewKeyFromSeed(seed).Public()).
		Expect("should return ed25519 public key")

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

// NewV4AsymmetricSecretKeyFromEd25519 creates a secret key from a standard Go object
func NewV4AsymmetricSecretKeyFromEd25519(privateKey ed25519.PrivateKey) (V4AsymmetricSecretKey, error) {
	return NewV4AsymmetricSecretKeyFromBytes([]byte(privateKey))
}

// NewV4AsymmetricSecretKeyFromSeed creates a secret key from a seed (hex)
func NewV4AsymmetricSecretKeyFromSeed(hexEncoded string) (V4AsymmetricSecretKey, error) {
	var seedBytes []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&seedBytes); err != nil {
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
	return encoding.HexEncode(k.ExportBytes())
}

// ExportBytes exports the key as raw byte array
func (k V4SymmetricKey) ExportBytes() []byte {
	return k.material[:]
}

// V4SymmetricKeyFromHex constructs a key from hex
func V4SymmetricKeyFromHex(hexEncoded string) (V4SymmetricKey, error) {
	var bytes []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&bytes); err != nil {
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
