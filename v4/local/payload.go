package local

import "github.com/pkg/errors"

// Payload v4 local payload
type Payload struct {
	nonce      [32]byte
	cipherText []byte
	tag        [32]byte
}

func (p Payload) Bytes() []byte {
	return append(append(p.nonce[:], p.cipherText...), p.tag[:]...)
}

func NewPayload(bytes []byte) (Payload, error) {
	if len(bytes) <= 32+32 {
		var p Payload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	macOffset := len(bytes) - 32

	var nonce [32]byte
	var cipherText []byte
	var tag [32]byte

	copy(bytes[0:32], nonce[:])
	copy(bytes[32:macOffset], cipherText[:])
	copy(bytes[macOffset:], tag[:])

	return Payload{nonce, cipherText, tag}, nil
}
