package hashing

import (
	"hash"

	"golang.org/x/crypto/blake2b"
)

// GenericHash The same as crypto_generichash as referred to in the Paseto spec
func GenericHash(in, out, key []byte) {
	var blake hash.Hash
	var err error

	if blake, err = blake2b.New(len(out), key); err != nil {
		panic(err)
	}

	if _, err = blake.Write(in); err != nil {
		panic(err)
	}

	copy(out, blake.Sum(nil))
}
