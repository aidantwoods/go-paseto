package paseto

import (
	"crypto/hmac"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20"
)

func V4LocalEncrypt(p Packet, key V4SymmetricKey, implicit []byte) (Message, error) {
	return v4LocalEncrypt(p, key, implicit, nil)
}

func v4LocalEncrypt(p Packet, key V4SymmetricKey, implicit []byte, unitTestNonce []byte) (Message, error) {
	var nonce [32]byte

	if unitTestNonce != nil {
		if len(unitTestNonce) != 32 {
			var m Message
			return m, errors.New("Unit test nonce incorrect length")
		}

		copy(nonce[:], unitTestNonce)
	} else {
		_, err := io.ReadFull(rand.Reader, nonce[:])

		if err != nil {
			panic("CSPRNG failure")
		}
	}

	encKey, authKey, nonce2 := key.split(nonce)

	cipher, err := chacha20.NewUnauthenticatedCipher(encKey[:], nonce2[:])

	if err != nil {
		panic("Cannot construct cipher")
	}

	cipherText := make([]byte, len(p.Content))
	cipher.XORKeyStream(cipherText, p.Content)

	header := []byte(V4Local.Header())

	preAuth := pae(header, nonce[:], cipherText, p.Footer, implicit)

	var tag [32]byte
	genericHash(preAuth, tag[:], authKey[:])

	return newMessageFromPayload(V4LocalPayload{nonce, cipherText, tag}, p.Footer), nil
}

func V4LocalDecrypt(message Message, key V4SymmetricKey, implicit []byte) (Packet, error) {
	var payload V4LocalPayload
	var ok bool

	if payload, ok = message.payload.(V4LocalPayload); message.Header() != V4Local.Header() || !ok {
		var p Packet
		return p, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
	}

	nonce, cipherText, givenTag := payload.nonce, payload.cipherText, payload.tag
	encKey, authKey, nonce2 := key.split(nonce)

	cipher, err := chacha20.NewUnauthenticatedCipher(encKey[:], nonce2[:])

	if err != nil {
		panic("Cannot construct cipher")
	}

	header := []byte(V4Local.Header())

	preAuth := pae(header, nonce[:], cipherText, message.footer, implicit)

	var expectedTag [32]byte
	genericHash(preAuth, expectedTag[:], authKey[:])

	if !hmac.Equal(expectedTag[:], givenTag[:]) {
		var p Packet
		return p, errors.Errorf("Bad message authentication code")
	}

	plainText := make([]byte, len(cipherText))
	cipher.XORKeyStream(plainText, cipherText)

	return Packet{plainText, message.footer}, nil
}
