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
		var p v3LocalPayload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	macOffset := len(bytes) - 48

	var nonce [32]byte
	cipherText := make([]byte, macOffset-32)
	var tag [48]byte

	copy(nonce[:], bytes[0:32])
	copy(cipherText, bytes[32:macOffset])
	copy(tag[:], bytes[macOffset:])

	return v3LocalPayload{nonce, cipherText, tag}, nil
}
