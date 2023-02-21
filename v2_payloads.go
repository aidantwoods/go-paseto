package paseto

import t "aidanwoods.dev/go-result"

type v2PublicPayload struct {
	message   []byte
	signature [64]byte
}

func (p v2PublicPayload) bytes() []byte {
	return append(p.message, p.signature[:]...)
}

func newV2PublicPayload(bytes []byte) t.Result[v2PublicPayload] {
	signatureOffset := len(bytes) - 64
	if signatureOffset < 0 {
		return t.Err[v2PublicPayload](errorPayloadShort)
	}

	message := make([]byte, len(bytes)-64)
	copy(message, bytes[:signatureOffset])

	var signature [64]byte
	copy(signature[:], bytes[signatureOffset:])

	return t.Ok(v2PublicPayload{message, signature})
}

type v2LocalPayload struct {
	nonce      [24]byte
	cipherText []byte
}

func (p v2LocalPayload) bytes() []byte {
	return append(p.nonce[:], p.cipherText...)
}

func newV2LocalPayload(bytes []byte) t.Result[v2LocalPayload] {
	if len(bytes) <= 24 {
		return t.Err[v2LocalPayload](errorPayloadShort)
	}
	var nonce [24]byte
	copy(nonce[:], bytes[0:24])

	cipherText := make([]byte, len(bytes)-24)
	copy(cipherText, bytes[24:])

	return t.Ok(v2LocalPayload{nonce, cipherText})
}
