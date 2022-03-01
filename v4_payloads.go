package paseto

import (
	"github.com/pkg/errors"
)

type v4PublicPayload struct {
	message   []byte
	signature [64]byte
}

func (p v4PublicPayload) bytes() []byte {
	return append(p.message, p.signature[:]...)
}

func newV4PublicPayload(bytes []byte) (v4PublicPayload, error) {
	signatureOffset := len(bytes) - 64

	if signatureOffset < 0 {
		return v4PublicPayload{}, errors.New("Payload is not long enough to be a valid Paseto message")
	}

	message := make([]byte, len(bytes)-64)
	copy(message, bytes[:signatureOffset])

	var signature [64]byte
	copy(signature[:], bytes[signatureOffset:])

	return v4PublicPayload{message, signature}, nil
}

type v4LocalPayload struct {
	nonce      [32]byte
	cipherText []byte
	tag        [32]byte
}

func (p v4LocalPayload) bytes() []byte {
	return append(append(p.nonce[:], p.cipherText...), p.tag[:]...)
}

func newV4LocalPayload(bytes []byte) (v4LocalPayload, error) {
	if len(bytes) <= 32+32 {
		return v4LocalPayload{}, errors.New("Payload is not long enough to be a valid Paseto message")
	}

	macOffset := len(bytes) - 32

	var nonce [32]byte
	copy(nonce[:], bytes[0:32])

	cipherText := make([]byte, macOffset-32)
	copy(cipherText, bytes[32:macOffset])

	var tag [32]byte
	copy(tag[:], bytes[macOffset:])

	return v4LocalPayload{nonce, cipherText, tag}, nil
}
