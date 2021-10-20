package paseto

import (
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/aidantwoods/go-paseto/internal/hashing"
	"github.com/pkg/errors"
)

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
