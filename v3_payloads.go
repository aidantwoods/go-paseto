package paseto

import (
	"github.com/pkg/errors"
)

type v3LocalPayload struct {
	nonce      [32]byte
	cipherText []byte
	tag        [48]byte
}

func (p v3LocalPayload) bytes() []byte {
	return append(append(p.nonce[:], p.cipherText...), p.tag[:]...)
}

func newV3LocalPayload(bytes []byte) (v3LocalPayload, error) {
	if len(bytes) <= 32+48 {
		return v3LocalPayload{}, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	macOffset := len(bytes) - 48

	var nonce [32]byte
	copy(nonce[:], bytes[0:32])

	cipherText := make([]byte, macOffset-32)
	copy(cipherText, bytes[32:macOffset])

	var tag [48]byte
	copy(tag[:], bytes[macOffset:])

	return v3LocalPayload{nonce, cipherText, tag}, nil
}
