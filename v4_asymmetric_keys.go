package paseto

import (
	"crypto/ed25519"
	"encoding/hex"

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
