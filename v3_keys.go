package paseto

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

// V3SymmetricKey v3 local symmetric key
type V3SymmetricKey struct {
	material [32]byte
}

// NewV3SymmetricKey generates a new symmetric key for encryption
func NewV3SymmetricKey() V3SymmetricKey {
	var material [32]byte
	_, err := io.ReadFull(rand.Reader, material[:])

	if err != nil {
		panic("CSPRNG failure")
	}

	return V3SymmetricKey{material}
}

// ExportHex exports the key as hex for storage
func (k V3SymmetricKey) ExportHex() string {
	return hex.EncodeToString(k.material[:])
}

// V3SymmetricKeyFromHex constructs a key from hex
func V3SymmetricKeyFromHex(hexEncoded string) (V3SymmetricKey, error) {
	bytes, err := hex.DecodeString(hexEncoded)
	if err != nil {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3SymmetricKey(), err
	}

	if len(bytes) != 32 {
		// even though we return error, return a random key here rather than
		// a nil key
		return NewV3SymmetricKey(), errors.New("Key incorrect length")
	}

	var material [32]byte
	copy(material[:], bytes)

	return V3SymmetricKey{material}, nil
}

func (k V3SymmetricKey) split(nonce [32]byte) (encKey [32]byte, authKey [48]byte, nonce2 [16]byte) {
	var tmp [48]byte
	kdf := hkdf.New(
		sha512.New384,
		k.material[:],
		nil,
		append([]byte("paseto-encryption-key"), nonce[:]...),
	)
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
