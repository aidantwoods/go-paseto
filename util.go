package paseto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// Pae Pre Auth Encode
func pae(pieces ...[]byte) []byte {
	buffer := &bytes.Buffer{}

	// MSB should be zero
	binary.Write(buffer, binary.LittleEndian, int64(len(pieces)))

	for i := range pieces {
		// MSB should be zero
		binary.Write(buffer, binary.LittleEndian, int64(len(pieces[i])))
		buffer.Write(pieces[i])
	}

	return buffer.Bytes()
}

func b64urlEncode(bytes []byte) string {
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(bytes)))

	base64.RawURLEncoding.Encode(encoded, bytes)

	return string(encoded)
}

func b64urlDecode(encoded string) ([]byte, error) {
	var bytes []byte
	var err error

	if bytes, err = base64.RawURLEncoding.DecodeString(encoded); err != nil {
		return nil, err
	}

	return bytes, nil
}

func genericHash(in, out, key []byte, outputLength int) {
	var blake hash.Hash
	var err error

	if len(out) != outputLength {
		panic("Insufficient out length")
	}

	if blake, err = blake2b.New(outputLength, key); err != nil {
		panic(err)
	}

	if _, err = blake.Write(in); err != nil {
		panic(err)
	}

	copy(out, blake.Sum(nil))
}
