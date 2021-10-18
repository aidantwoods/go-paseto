package paseto

import (
	"github.com/pkg/errors"
)

// Payload v4 local payload
type V4LocalPayload struct {
	nonce      [32]byte
	cipherText []byte
	tag        [32]byte
}

func (p V4LocalPayload) Bytes() []byte {
	return append(append(p.nonce[:], p.cipherText...), p.tag[:]...)
}

func NewV4LocalPayload(bytes []byte) (V4LocalPayload, error) {
	if len(bytes) <= 32+32 {
		var p V4LocalPayload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	macOffset := len(bytes) - 32

	var nonce [32]byte
	cipherText := make([]byte, macOffset-32)
	var tag [32]byte

	copy(nonce[:], bytes[0:32])
	copy(cipherText, bytes[32:macOffset])
	copy(tag[:], bytes[macOffset:])

	return V4LocalPayload{nonce, cipherText, tag}, nil
}
