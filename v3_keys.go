package paseto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"math/big"

	"aidanwoods.dev/go-paseto/internal/encoding"
	"aidanwoods.dev/go-paseto/internal/random"
	t "aidanwoods.dev/go-result"
	"golang.org/x/crypto/hkdf"
)

// V3AsymmetricPublicKey v3 public public key
type V3AsymmetricPublicKey struct {
	material ecdsa.PublicKey
}

// NewV3AsymmetricPublicKeyFromHex Construct a v3 public key from hex
func NewV3AsymmetricPublicKeyFromHex(hexEncoded string) (V3AsymmetricPublicKey, error) {
	var publicKeyBytes []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&publicKeyBytes); err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3AsymmetricSecretKey().Public(), err
	}

	return NewV3AsymmetricPublicKeyFromBytes(publicKeyBytes)
}

// NewV3AsymmetricPublicKeyFromBytes Construct a v3 public key from bytes
func NewV3AsymmetricPublicKeyFromBytes(publicKeyBytes []byte) (V3AsymmetricPublicKey, error) {
	if len(publicKeyBytes) != 49 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3AsymmetricSecretKey().Public(), errorKeyLength(49, len(publicKeyBytes))
	}

	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = elliptic.P384()
	publicKey.X, publicKey.Y = elliptic.UnmarshalCompressed(elliptic.P384(), publicKeyBytes)

	return V3AsymmetricPublicKey{*publicKey}, nil
}

// NewV3AsymmetricPublicKeyFromEcdsa Construct a v3 public key from a standard Go object
func NewV3AsymmetricPublicKeyFromEcdsa(publicKey ecdsa.PublicKey) (V3AsymmetricPublicKey, error) {
	if publicKey.Curve != elliptic.P384() {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3AsymmetricSecretKey().Public(), errorKeyWrongCurve
	}

	// Compress the key for the expected curve and go through the compressed point initialiser
	// This guarantees the result we get is on the curve.
	parsedPubKey, err := NewV3AsymmetricPublicKeyFromBytes(elliptic.MarshalCompressed(
		elliptic.P384(),
		publicKey.X,
		publicKey.Y,
	))
	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return parsedPubKey, err
	}

	// If somehow the key is different after going through the compressed initialiser, something
	// has gone very wrong.
	if !publicKey.Equal(&parsedPubKey.material) {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3AsymmetricSecretKey().Public(), errorKeyInvalid
	}

	return parsedPubKey, nil
}

func (k V3AsymmetricPublicKey) compressed() []byte {
	return elliptic.MarshalCompressed(elliptic.P384(), k.material.X, k.material.Y)
}

// ExportHex export a V3AsymmetricPublicKey to hex for storage
func (k V3AsymmetricPublicKey) ExportHex() string {
	return encoding.HexEncode(k.ExportBytes())
}

// ExportBytes export a V3AsymmetricPublicKey to raw byte array
func (k V3AsymmetricPublicKey) ExportBytes() []byte {
	return k.compressed()
}

// V3AsymmetricSecretKey v3 public private key
type V3AsymmetricSecretKey struct {
	material ecdsa.PrivateKey
}

// Public returns the corresponding public key for a secret key
func (k V3AsymmetricSecretKey) Public() V3AsymmetricPublicKey {
	return V3AsymmetricPublicKey{k.material.PublicKey}
}

// ExportHex export a V3AsymmetricSecretKey to hex for storage
func (k V3AsymmetricSecretKey) ExportHex() string {
	return encoding.HexEncode(k.ExportBytes())
}

// ExportBytes export a V3AsymmetricSecretKey to raw byte array
func (k V3AsymmetricSecretKey) ExportBytes() []byte {
	return k.material.D.Bytes()
}

// NewV3AsymmetricSecretKey generate a new secret key for use with asymmetric
// cryptography. Don't forget to export the public key for sharing, DO NOT share
// this secret key.
func NewV3AsymmetricSecretKey() V3AsymmetricSecretKey {
	privateKey := t.NewResult(ecdsa.GenerateKey(elliptic.P384(), rand.Reader)).
		Expect("CSPRNG should not fail")

	return V3AsymmetricSecretKey{*privateKey}
}

// NewV3AsymmetricSecretKeyFromHex creates a secret key from hex
func NewV3AsymmetricSecretKeyFromHex(hexEncoded string) (V3AsymmetricSecretKey, error) {
	var secretBytes []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&secretBytes); err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3AsymmetricSecretKey(), err
	}

	return NewV3AsymmetricSecretKeyFromBytes(secretBytes)
}

// NewV3AsymmetricSecretKeyFromBytes creates a secret key from bytes
func NewV3AsymmetricSecretKeyFromBytes(secretBytes []byte) (V3AsymmetricSecretKey, error) {
	if len(secretBytes) != 48 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3AsymmetricSecretKey(), errorKeyLength(48, len(secretBytes))
	}

	privateKey := new(ecdsa.PrivateKey)
	privateKey.D = new(big.Int).SetBytes(secretBytes)

	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = elliptic.P384()
	publicKey.X, publicKey.Y = publicKey.Curve.ScalarBaseMult(privateKey.D.Bytes())

	privateKey.PublicKey = *publicKey

	return V3AsymmetricSecretKey{*privateKey}, nil
}

// NewV3AsymmetricSecretKeyFromBytes creates a secret key from a standard Go object
func NewV3AsymmetricSecretKeyFromEcdsa(privateKey ecdsa.PrivateKey) (V3AsymmetricSecretKey, error) {
	// basic sanity check that public key is associated with key material
	parsedPrivateKey, err := NewV3AsymmetricSecretKeyFromBytes(privateKey.D.Bytes())
	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return parsedPrivateKey, err
	}

	if !privateKey.Equal(&parsedPrivateKey.material) {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3AsymmetricSecretKey(), errorKeyInvalid
	}

	return parsedPrivateKey, nil
}

// V3SymmetricKey v3 local symmetric key
type V3SymmetricKey struct {
	material [32]byte
}

// NewV3SymmetricKey generates a new symmetric key for encryption
func NewV3SymmetricKey() V3SymmetricKey {
	var material [32]byte
	random.FillBytes(material[:])

	return V3SymmetricKey{material}
}

// ExportHex exports the key as hex for storage
func (k V3SymmetricKey) ExportHex() string {
	return encoding.HexEncode(k.ExportBytes())
}

// ExportBytes exports the key as raw byte array
func (k V3SymmetricKey) ExportBytes() []byte {
	return k.material[:]
}

// V3SymmetricKeyFromHex constructs a key from hex
func V3SymmetricKeyFromHex(hexEncoded string) (V3SymmetricKey, error) {
	var bytes []byte
	if err := encoding.HexDecode(hexEncoded).Ok(&bytes); err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3SymmetricKey(), err
	}

	return V3SymmetricKeyFromBytes(bytes)
}

// V3SymmetricKeyFromBytes constructs a key from bytes
func V3SymmetricKeyFromBytes(bytes []byte) (V3SymmetricKey, error) {
	if len(bytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3SymmetricKey(), errorKeyLength(32, len(bytes))
	}

	var material [32]byte
	copy(material[:], bytes)

	return V3SymmetricKey{material}, nil
}

func (k V3SymmetricKey) split(nonce [32]byte) (encKey [32]byte, authKey [48]byte, nonce2 [16]byte) {
	kdf := hkdf.New(
		sha512.New384,
		k.material[:],
		nil,
		append([]byte("paseto-encryption-key"), nonce[:]...),
	)

	var tmp [48]byte
	t.NewResult(io.ReadFull(kdf, tmp[:])).Expect("hkdf should not fail")

	copy(encKey[:], tmp[0:32])
	copy(nonce2[:], tmp[32:48])

	kdf = hkdf.New(
		sha512.New384,
		k.material[:],
		nil,
		append([]byte("paseto-auth-key-for-aead"), nonce[:]...),
	)
	t.NewResult(io.ReadFull(kdf, authKey[:])).Expect("hkdf should not fail")

	return encKey, authKey, nonce2
}
