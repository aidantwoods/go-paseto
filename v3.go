package paseto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"io"

	"github.com/aidantwoods/go-paseto/internal/encoding"
	"github.com/pkg/errors"
)

func v3LocalEncrypt(p packet, key V3SymmetricKey, implicit []byte, unitTestNonce []byte) Message {
	var nonce [32]byte

	if unitTestNonce != nil {
		if len(unitTestNonce) != 32 {
			panic("Unit test nonce incorrect length")
		}

		copy(nonce[:], unitTestNonce)
	} else {
		_, err := io.ReadFull(rand.Reader, nonce[:])

		if err != nil {
			panic("CSPRNG failure")
		}
	}

	encKey, authKey, nonce2 := key.split(nonce)

	blockCipher, err := aes.NewCipher(encKey[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	cipherText := make([]byte, len(p.content))
	cipher.NewCTR(blockCipher, nonce2[:]).XORKeyStream(cipherText, p.content)

	header := []byte(V3Local.Header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, p.footer, implicit)

	hm := hmac.New(sha512.New384, authKey[:])
	if _, err := hm.Write(preAuth); err != nil {
		panic(err)
	}
	var tag [48]byte
	copy(tag[:], hm.Sum(nil))

	return newMessageFromPayload(v3LocalPayload{nonce, cipherText, tag}, p.footer)
}

func v3LocalDecrypt(message Message, key V3SymmetricKey, implicit []byte) (packet, error) {
	var payload v3LocalPayload
	var ok bool

	if payload, ok = message.p.(v3LocalPayload); message.Header() != V3Local.Header() || !ok {
		var p packet
		return p, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
	}

	nonce, cipherText, givenTag := payload.nonce, payload.cipherText, payload.tag
	encKey, authKey, nonce2 := key.split(nonce)

	blockCipher, err := aes.NewCipher(encKey[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	header := []byte(message.Header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, message.footer, implicit)

	hm := hmac.New(sha512.New384, authKey[:])
	if _, err := hm.Write(preAuth); err != nil {
		panic(err)
	}
	var expectedTag [48]byte
	copy(expectedTag[:], hm.Sum(nil))

	if !hmac.Equal(expectedTag[:], givenTag[:]) {
		var p packet
		return p, errors.Errorf("Bad message authentication code")
	}

	plainText := make([]byte, len(cipherText))
	cipher.NewCTR(blockCipher, nonce2[:]).XORKeyStream(plainText, cipherText)

	return packet{plainText, message.footer}, nil
}
