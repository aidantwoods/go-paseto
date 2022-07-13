package paseto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"math/big"

	"aidanwoods.dev/go-paseto/internal/random"
	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

// V3AsymmetricPublicKey v3 public public key
type V3AsymmetricPublicKey struct {
	material ecdsa.PublicKey
}

// NewV3AsymmetricPublicKeyFromHex Construct a v3 public key from hex
func NewV3AsymmetricPublicKeyFromHex(hexEncoded string) (V3AsymmetricPublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(hexEncoded)

	if err != nil {

		return V3AsymmetricPublicKey{}, err
	}

	return NewV3AsymmetricPublicKeyFromBytes(publicKeyBytes)
}

// NewV3AsymmetricPublicKeyFromBytes Construct a v3 public key from bytes
func NewV3AsymmetricPublicKeyFromBytes(publicKeyBytes []byte) (V3AsymmetricPublicKey, error) {
	if len(publicKeyBytes) != 49 {

		return V3AsymmetricPublicKey{}, errors.New("Key incorrect length")
	}

	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = elliptic.P384()
	publicKey.X, publicKey.Y = elliptic.UnmarshalCompressed(elliptic.P384(), publicKeyBytes)

	return V3AsymmetricPublicKey{*publicKey}, nil
}

func (k V3AsymmetricPublicKey) compressed() []byte {
	return elliptic.MarshalCompressed(elliptic.P384(), k.material.X, k.material.Y)
}

// ExportHex export a V3AsymmetricPublicKey to hex for storage
func (k V3AsymmetricPublicKey) ExportHex() string {
	return hex.EncodeToString(k.ExportBytes())
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
	return hex.EncodeToString(k.ExportBytes())
}

// ExportBytes export a V3AsymmetricSecretKey to raw byte array
func (k V3AsymmetricSecretKey) ExportBytes() []byte {
	return k.material.D.Bytes()
}

// NewV3AsymmetricSecretKey generate a new secret key for use with asymmetric
// cryptography. Don't forget to export the public key for sharing, DO NOT share
// this secret key.
func NewV3AsymmetricSecretKey() V3AsymmetricSecretKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		panic("CSPRNG failure")
	}

	return V3AsymmetricSecretKey{*privateKey}
}

// NewV3AsymmetricSecretKeyFromHex creates a secret key from hex
func NewV3AsymmetricSecretKeyFromHex(hexEncoded string) (V3AsymmetricSecretKey, error) {
	secretBytes, err := hex.DecodeString(hexEncoded)

	if err != nil {

		return V3AsymmetricSecretKey{}, err
	}

	return NewV3AsymmetricSecretKeyFromBytes(secretBytes)
}

// NewV3AsymmetricSecretKeyFromBytes creates a secret key from bytes
func NewV3AsymmetricSecretKeyFromBytes(secretBytes []byte) (V3AsymmetricSecretKey, error) {
	if len(secretBytes) != 48 {

		return V3AsymmetricSecretKey{}, errors.New("Key incorrect length")
	}

	privateKey := new(ecdsa.PrivateKey)
	privateKey.D = new(big.Int).SetBytes(secretBytes)

	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = elliptic.P384()
	publicKey.X, publicKey.Y = publicKey.Curve.ScalarBaseMult(privateKey.D.Bytes())

	privateKey.PublicKey = *publicKey

	return V3AsymmetricSecretKey{*privateKey}, nil
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
	return hex.EncodeToString(k.ExportBytes())
}

// ExportBytes exports the key as raw byte array
func (k V3SymmetricKey) ExportBytes() []byte {
	return k.material[:]
}

// V3SymmetricKeyFromHex constructs a key from hex
func V3SymmetricKeyFromHex(hexEncoded string) (V3SymmetricKey, error) {
	bytes, err := hex.DecodeString(hexEncoded)
	if err != nil {

		return V3SymmetricKey{}, err
	}

	return V3SymmetricKeyFromBytes(bytes)
}

// V3SymmetricKeyFromBytes constructs a key from bytes
func V3SymmetricKeyFromBytes(bytes []byte) (V3SymmetricKey, error) {
	if len(bytes) != 32 {

		return V3SymmetricKey{}, errors.New("Key incorrect length")
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
	if _, err := io.ReadFull(kdf, tmp[:]); err != nil {
		panic(err)
	}

	copy(encKey[:], tmp[0:32])
	copy(nonce2[:], tmp[32:48])

	kdf = hkdf.New(
		sha512.New384,
		k.material[:],
		nil,
		append([]byte("paseto-auth-key-for-aead"), nonce[:]...),
	)
	if _, err := io.ReadFull(kdf, authKey[:]); err != nil {
		panic(err)
	}

	return encKey, authKey, nonce2
}
