package hashing

import (
	t "aidanwoods.dev/go-result"
	"golang.org/x/crypto/blake2b"
)

// GenericHash The same as crypto_generichash as referred to in the Paseto spec
func GenericHash(in, out, key []byte) {
	blake := t.NewResult(blake2b.New(len(out), key)).
		Expect("blake2 hasher construction should be provided with valid length inputs")

	t.NewResult(blake.Write(in)).
		Expect("writing into hasher should not fail")

	copy(out, blake.Sum(nil))
}
