package encoding

import (
	"bytes"
	"encoding/binary"
)

// Pae Pre Auth Encode
func Pae(pieces ...[]byte) []byte {
	buffer := &bytes.Buffer{}

	// MSB should be zero
	if err := binary.Write(buffer, binary.LittleEndian, int64(len(pieces))); err != nil {
		panic("Cannot write to buffer")
	}

	for i := range pieces {
		// MSB should be zero
		if err := binary.Write(buffer, binary.LittleEndian, int64(len(pieces[i]))); err != nil {
			panic("Cannot write to buffer")
		}
		if _, err := buffer.Write(pieces[i]); err != nil {
			panic("Cannot write to buffer")
		}
	}

	return buffer.Bytes()
}
