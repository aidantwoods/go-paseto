package paseto

// V4SymmetricKey v4 local symmetric key
type V4SymmetricKey struct {
	material [32]byte
}

func (key V4SymmetricKey) split(nonce [32]byte) (encKey [32]byte, authkey [32]byte, nonce2 [24]byte) {
	var tmp [56]byte
	genericHash(append([]byte("paseto-encryption-key"), nonce[:]...), tmp[:], key.material[:], 56)

	copy(encKey[:], tmp[0:32])
	copy(nonce2[:], tmp[32:56])

	genericHash(append([]byte("paseto-auth-key-for-aead"), nonce[:]...), authkey[:], key.material[:], 32)

	return encKey, authkey, nonce2
}
