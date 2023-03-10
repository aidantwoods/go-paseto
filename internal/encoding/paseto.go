package encoding

import (
	"bytes"
	"encoding/binary"

	t "aidanwoods.dev/go-result"
)

// Pae Pre Auth Encode
func Pae(pieces ...[]byte) []byte {
	buffer := &bytes.Buffer{}

	// MSB should be zero
	t.NewVoidResult(binary.Write(buffer, binary.LittleEndian, int64(len(pieces)))).
		Expect("writing to buffer should not fail")

	for i := range pieces {
		// MSB should be zero
		t.NewVoidResult(binary.Write(buffer, binary.LittleEndian, int64(len(pieces[i])))).
			Expect("writing to buffer should not fail")

		t.NewResult(buffer.Write(pieces[i])).
			Expect("writing to buffer should not fail")
	}

	return buffer.Bytes()
}
