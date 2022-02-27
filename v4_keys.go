package paseto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/aidantwoods/go-paseto/internal/hashing"
	"github.com/pkg/errors"
)

// V4AsymmetricPublicKey v4 public public key
type V4AsymmetricPublicKey struct {
	material ed25519.PublicKey
}

func NewV4AsymmetricPublicKeyFromHex(hexEncoded string) (V4AsymmetricPublicKey, error) {
	publicKey, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey().Public(), err
	}

	if len(publicKey) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey().Public(), errors.New("Key incorrect length")
	}

	return V4AsymmetricPublicKey{publicKey}, nil
}

func (k V4AsymmetricPublicKey) ExportHex() string {
	return hex.EncodeToString(k.material)
}

// V4AsymmetricSecretKey v4 public private key
type V4AsymmetricSecretKey struct {
	material ed25519.PrivateKey
}

func (k V4AsymmetricSecretKey) Public() V4AsymmetricPublicKey {
	material, ok := k.material.Public().(ed25519.PublicKey)

	if !ok {
		panic("Wrong public key returned")
	}

	return V4AsymmetricPublicKey{material}
}

func (k V4AsymmetricSecretKey) ExportHex() string {
	return hex.EncodeToString(k.material)
}

func (k V4AsymmetricSecretKey) ExportSeedHex() string {
	return hex.EncodeToString(k.material.Seed())
}

func NewV4AsymmetricSecretKey() V4AsymmetricSecretKey {
	_, privateKey, err := ed25519.GenerateKey(nil)

	if err != nil {
		panic("CSPRNG failure")
	}

	return V4AsymmetricSecretKey{privateKey}
}

func NewV4AsymmetricSecretKeyFromHex(hexEncoded string) (V4AsymmetricSecretKey, error) {
	privateKey, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey(), err
	}

	if len(privateKey) != 64 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4AsymmetricSecretKey(), errors.New("Key incorrect length")
	}

	return V4AsymmetricSecretKey{privateKey}, nil
}

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
		return NewV4AsymmetricSecretKey(), errors.New("Key incorrect length")
	}

	return V4AsymmetricSecretKey{ed25519.NewKeyFromSeed(seedBytes)}, nil
}

// V4SymmetricKey v4 local symmetric key
type V4SymmetricKey struct {
	material [32]byte
}

func NewV4SymmetricKey() V4SymmetricKey {
	var material [32]byte

	_, err := io.ReadFull(rand.Reader, material[:])

	if err != nil {
		panic("CSPRNG failure")
	}

	return V4SymmetricKey{material}
}

func (k V4SymmetricKey) ExportHex() string {
	return hex.EncodeToString(k.material[:])
}

func V4SymmetricKeyFromHex(hexEncoded string) (V4SymmetricKey, error) {
	bytes, err := hex.DecodeString(hexEncoded)

	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4SymmetricKey(), err
	}

	if len(bytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV4SymmetricKey(), errors.New("Key incorrect length")
	}

	var material [32]byte

	copy(material[:], bytes)

	return V4SymmetricKey{material}, nil
}

func (key V4SymmetricKey) split(nonce [32]byte) (encKey [32]byte, authkey [32]byte, nonce2 [24]byte) {
	var tmp [56]byte
	hashing.GenericHash(append([]byte("paseto-encryption-key"), nonce[:]...), tmp[:], key.material[:])

	copy(encKey[:], tmp[0:32])
	copy(nonce2[:], tmp[32:56])

	hashing.GenericHash(append([]byte("paseto-auth-key-for-aead"), nonce[:]...), authkey[:], key.material[:])

	return encKey, authkey, nonce2
}
