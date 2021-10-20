package encoding

import (
	"encoding/base64"
	"errors"
	"strings"
)

var b64 = base64.RawURLEncoding.Strict()

// Encode Standard encoding for Paseto is URL safe base64 with no padding
func Encode(bytes []byte) string {
	return b64.EncodeToString(bytes)
}

// Decode Standard decoding for Paseto is URL safe base64 with no padding
func Decode(encoded string) ([]byte, error) {
	// From: https://pkg.go.dev/encoding/base64#Encoding.Strict
	// Note that the input is still malleable, as new line characters (CR and LF) are still ignored.
	if strings.ContainsAny(encoded, "\n\r") {
		return nil, errors.New("Input may not contain new lines")
	}

	return b64.DecodeString(encoded)
}
