package local

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

// SymmetricKey v4 local symmetric key
type SymmetricKey struct {
	material [32]byte
}

func (key SymmetricKey) split(nonce [32]byte) (encKey [32]byte, authkey [32]byte, nonce2 [24]byte, err error) {
	var encBlake hash.Hash

	if encBlake, err = blake2b.New(56, key.material[:]); err != nil {
		return encKey, authkey, nonce2, err
	}

	encBlake.Write([]byte("paseto-encryption-key"))
	encBlake.Write(nonce[:])

	var tmp [56]byte
	encBlake.Sum(tmp[:])

	copy(tmp[0:32], encKey[:])
	copy(tmp[32:56], nonce2[:])

	var authBlake hash.Hash

	if authBlake, err = blake2b.New(32, key.material[:]); err != nil {
		return encKey, authkey, nonce2, err
	}

	authBlake.Write([]byte("paseto-auth-key-for-aead"))
	authBlake.Write(nonce[:])
	authBlake.Sum(authkey[:])

	return encKey, authkey, nonce2, nil
}
