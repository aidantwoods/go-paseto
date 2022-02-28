package paseto

import (
	"github.com/pkg/errors"
)

type v2PublicPayload struct {
	message   []byte
	signature [64]byte
}

func (p v2PublicPayload) bytes() []byte {
	return append(p.message, p.signature[:]...)
}

func newV2PublicPayload(bytes []byte) (v2PublicPayload, error) {
	signatureOffset := len(bytes) - 64

	if signatureOffset < 0 {
		var p v2PublicPayload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	message := make([]byte, len(bytes)-64)
	var signature [64]byte

	copy(message, bytes[:signatureOffset])
	copy(signature[:], bytes[signatureOffset:])

	return v2PublicPayload{message, signature}, nil
}

type v2LocalPayload struct {
	nonce      [24]byte
	cipherText []byte
}

func (p v2LocalPayload) bytes() []byte {
	return append(p.nonce[:], p.cipherText...)
}

func newV2LocalPayload(bytes []byte) (v2LocalPayload, error) {
	if len(bytes) <= 24 {
		var p v2LocalPayload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	var nonce [24]byte
	cipherText := make([]byte, len(bytes)-24)

	copy(nonce[:], bytes[0:24])
	copy(cipherText, bytes[24:])

	return v2LocalPayload{nonce, cipherText}, nil
}
