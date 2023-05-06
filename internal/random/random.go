package random

import (
	"crypto/rand"
	"io"

	t "aidanwoods.dev/go-result"
)

// FillBytes fills out with random bytes from the OS CSPRNG, or panics
func FillBytes(out []byte) {
	t.NewResult(io.ReadFull(rand.Reader, out[:])).Expect("CSPRNG failure")
}

// UseProvidedOrFillBytes will fill `out' with unitTestNonce, provided it is
// not nil and unitTestNonce matches the length of `out' exactly.
// If unitTestNonce's length is incorrect, this will panic.
// If unitTestNonce is nil, `out' will be filled with CSPRNG bytes using
// FillBytes.
//
// This allows us to unit test where encryption would otherwise be
// non-deterministic. Functions which accept unitTestNonce will not be exported
// and so do not present a footgun in the user-available API.
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
