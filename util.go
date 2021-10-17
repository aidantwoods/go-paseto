package paseto

import (
	"bytes"
	"encoding/binary"
)

// Pae Pre Auth Encode
func Pae(pieces ...[]byte) []byte {
	// MSB should be zero
	count := int64(len(pieces))
	buffer := &bytes.Buffer{}

	binary.Write(buffer, binary.LittleEndian, count)

	for i := range pieces {
		// MSB should be zero
		binary.Write(buffer, binary.LittleEndian, int64(len(pieces[i])))
		buffer.Write(pieces[i])
	}

	return buffer.Bytes()
}
