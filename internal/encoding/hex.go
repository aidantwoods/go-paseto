package encoding

import (
	"encoding/hex"

	t "aidanwoods.dev/go-result"
)

// Encode hex
func HexEncode(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

// Decode hex
func HexDecode(encoded string) t.Result[[]byte] {
	return t.NewResult(hex.DecodeString(encoded))
}
