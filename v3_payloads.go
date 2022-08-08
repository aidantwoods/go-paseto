package paseto

type v3PublicPayload struct {
	message   []byte
	signature [96]byte
}

func (p v3PublicPayload) bytes() []byte {
	return append(p.message, p.signature[:]...)
}

func newV3PublicPayload(bytes []byte) (v3PublicPayload, error) {
	signatureOffset := len(bytes) - 96

	if signatureOffset < 0 {
		return v3PublicPayload{}, errorPayloadShort
	}

	message := make([]byte, len(bytes)-96)
	copy(message, bytes[:signatureOffset])

	var signature [96]byte
	copy(signature[:], bytes[signatureOffset:])

	return v3PublicPayload{message, signature}, nil
}

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
		return v3LocalPayload{}, errorPayloadShort
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
