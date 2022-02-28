package paseto

import (
	"github.com/pkg/errors"
)

// v4PublicPayload v4 local payload
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
		var p v4PublicPayload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	message := make([]byte, len(bytes)-64)
	var signature [64]byte

	copy(message, bytes[:signatureOffset])
	copy(signature[:], bytes[signatureOffset:])

	return v4PublicPayload{message, signature}, nil
}

// v4LocalPayload v4 local payload
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
		var p v4LocalPayload
		return p, errors.New("Payload is not long enough to by a valid Paseto message")
	}

	macOffset := len(bytes) - 32

	var nonce [32]byte
	cipherText := make([]byte, macOffset-32)
	var tag [32]byte

	copy(nonce[:], bytes[0:32])
	copy(cipherText, bytes[32:macOffset])
	copy(tag[:], bytes[macOffset:])

	return v4LocalPayload{nonce, cipherText, tag}, nil
}
