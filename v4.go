package paseto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"io"

	"github.com/aidantwoods/go-paseto/internal/encoding"
	"github.com/aidantwoods/go-paseto/internal/hashing"
	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20"
)

func V4PublicSign(packet Packet, key V4AsymmetricSecretKey, implicit []byte) Message {
	data, footer := packet.Content, packet.Footer
	header := []byte(V4Public.Header())

	m2 := encoding.Pae(header, data, footer, implicit)

	sig := ed25519.Sign(key.material, m2)

	if len(sig) != 64 {
		panic("Bad signature length")
	}

	var signature [64]byte
	copy(signature[:], sig)

	return newMessageFromPayload(V4PublicPayload{data, signature}, footer)
}

func V4PublicVerify(message Message, key V4AsymmetricPublicKey, implicit []byte) (Packet, error) {
	var payload V4PublicPayload
	var ok bool

	if payload, ok = message.payload.(V4PublicPayload); message.Header() != V4Public.Header() || !ok {
		var p Packet
		return p, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
	}

	header, footer := []byte(message.Header()), message.footer
	data := payload.message

	m2 := encoding.Pae(header, data, footer, implicit)

	if !ed25519.Verify(key.material, m2, payload.signature[:]) {
		var p Packet
		return p, errors.Errorf("Bad signature")
	}

	return Packet{data, footer}, nil
}

func V4LocalEncrypt(p Packet, key V4SymmetricKey, implicit []byte) Message {
	return v4LocalEncrypt(p, key, implicit, nil)
}

func v4LocalEncrypt(p Packet, key V4SymmetricKey, implicit []byte, unitTestNonce []byte) Message {
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

	cipher, err := chacha20.NewUnauthenticatedCipher(encKey[:], nonce2[:])

	if err != nil {
		panic("Cannot construct cipher")
	}

	cipherText := make([]byte, len(p.Content))
	cipher.XORKeyStream(cipherText, p.Content)

	header := []byte(V4Local.Header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, p.Footer, implicit)

	var tag [32]byte
	hashing.GenericHash(preAuth, tag[:], authKey[:])

	return newMessageFromPayload(V4LocalPayload{nonce, cipherText, tag}, p.Footer)
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

	header := []byte(message.Header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, message.footer, implicit)

	var expectedTag [32]byte
	hashing.GenericHash(preAuth, expectedTag[:], authKey[:])

	if !hmac.Equal(expectedTag[:], givenTag[:]) {
		var p Packet
		return p, errors.Errorf("Bad message authentication code")
	}

	plainText := make([]byte, len(cipherText))
	cipher.XORKeyStream(plainText, cipherText)

	return Packet{plainText, message.footer}, nil
}
