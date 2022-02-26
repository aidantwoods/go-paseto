package paseto

import (
	"github.com/pkg/errors"
)

// V4PublicPayload v4 local payload
type V4PublicPayload struct {
	message   []byte
	signature [64]byte
}

func (p V4PublicPayload) Bytes() []byte {
	return append(p.message, p.signature[:]...)
}

func NewV4PublicPayload(bytes []byte) (V4PublicPayload, error) {
	signatureOffset := len(bytes) - 64

	if signatureOffset < 0 {
		var p V4PublicPayload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	message := make([]byte, len(bytes)-64)
	var signature [64]byte

	copy(message, bytes[:signatureOffset])
	copy(signature[:], bytes[signatureOffset:])

	return V4PublicPayload{message, signature}, nil
}

// V4LocalPayload v4 local payload
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
