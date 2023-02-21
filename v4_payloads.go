package paseto

import t "aidanwoods.dev/go-result"

type v4PublicPayload struct {
	message   []byte
	signature [64]byte
}

func (p v4PublicPayload) bytes() []byte {
	return append(p.message, p.signature[:]...)
}

func newV4PublicPayload(bytes []byte) t.Result[v4PublicPayload] {
	signatureOffset := len(bytes) - 64

	if signatureOffset < 0 {
		return t.Err[v4PublicPayload](errorPayloadShort)
	}

	message := make([]byte, len(bytes)-64)
	copy(message, bytes[:signatureOffset])

	var signature [64]byte
	copy(signature[:], bytes[signatureOffset:])

	return t.Ok(v4PublicPayload{message, signature})
}

type v4LocalPayload struct {
	nonce      [32]byte
	cipherText []byte
	tag        [32]byte
}

func (p v4LocalPayload) bytes() []byte {
	return append(append(p.nonce[:], p.cipherText...), p.tag[:]...)
}

func newV4LocalPayload(bytes []byte) t.Result[v4LocalPayload] {
	if len(bytes) <= 32+32 {
		return t.Err[v4LocalPayload](errorPayloadShort)
	}

	macOffset := len(bytes) - 32

	var nonce [32]byte
	copy(nonce[:], bytes[0:32])

	cipherText := make([]byte, macOffset-32)
	copy(cipherText, bytes[32:macOffset])

	var tag [32]byte
	copy(tag[:], bytes[macOffset:])

	return t.Ok(v4LocalPayload{nonce, cipherText, tag})
}
