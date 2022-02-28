package random

import (
	"crypto/rand"
	"io"
)

// FillBytes fills out with random bytes from the OS CSPRNG, or panics
func FillBytes(out []byte) {
	_, err := io.ReadFull(rand.Reader, out[:])

	if err != nil {
		panic("CSPRNG failure")
	}
}

// UseProvidedOrFillBytes will fill out with unitTestNonce if provided is not
// nil and matches the length of out exactly.
// If unitTestNonce length is incorrect this will panic.
// If provided is nil, out will be filled with CSPRNG bytes using FillBytes.
func UseProvidedOrFillBytes(unitTestNonce, out []byte) {
	if unitTestNonce != nil {
		if len(unitTestNonce) != len(out) {
			panic("Unit test nonce incorrect length")
		}

		copy(out[:], unitTestNonce)
	} else {
		FillBytes(out[:])
	}
}
