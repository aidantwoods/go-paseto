package paseto

import (
	"crypto/ed25519"
	"crypto/hmac"

	"github.com/aidantwoods/go-paseto/internal/encoding"
	"github.com/aidantwoods/go-paseto/internal/hashing"
	"github.com/aidantwoods/go-paseto/internal/random"
	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20"
)

func v4PublicSign(packet packet, key V4AsymmetricSecretKey, implicit []byte) Message {
	data, footer := packet.content, packet.footer
	header := []byte(V4Public.Header())

	m2 := encoding.Pae(header, data, footer, implicit)

	sig := ed25519.Sign(key.material, m2)

	if len(sig) != 64 {
		panic("Bad signature length")
	}

	var signature [64]byte
	copy(signature[:], sig)

	return newMessageFromPayload(v4PublicPayload{data, signature}, footer)
}

func v4PublicVerify(message Message, key V4AsymmetricPublicKey, implicit []byte) (packet, error) {
	payload, ok := message.p.(v4PublicPayload)
	if message.Header() != V4Public.Header() || !ok {
		return packet{}, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
	}

	header, footer := []byte(message.Header()), message.footer
	data := payload.message

	m2 := encoding.Pae(header, data, footer, implicit)

	if !ed25519.Verify(key.material, m2, payload.signature[:]) {
		return packet{}, errors.Errorf("Bad signature")
	}

	return packet{data, footer}, nil
}

func v4LocalEncrypt(p packet, key V4SymmetricKey, implicit []byte, unitTestNonce []byte) Message {
	var nonce [32]byte
	random.UseProvidedOrFillBytes(unitTestNonce, nonce[:])

	encKey, authKey, nonce2 := key.split(nonce)

	cipher, err := chacha20.NewUnauthenticatedCipher(encKey[:], nonce2[:])

	if err != nil {
		panic("Cannot construct cipher")
	}

	cipherText := make([]byte, len(p.content))
	cipher.XORKeyStream(cipherText, p.content)

	header := []byte(V4Local.Header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, p.footer, implicit)

	var tag [32]byte
	hashing.GenericHash(preAuth, tag[:], authKey[:])

	return newMessageFromPayload(v4LocalPayload{nonce, cipherText, tag}, p.footer)
}

func v4LocalDecrypt(message Message, key V4SymmetricKey, implicit []byte) (packet, error) {
	payload, ok := message.p.(v4LocalPayload)
	if message.Header() != V4Local.Header() || !ok {
		return packet{}, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
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
		return packet{}, errors.Errorf("Bad message authentication code")
	}

	plainText := make([]byte, len(cipherText))
	cipher.XORKeyStream(plainText, cipherText)

	return packet{plainText, message.footer}, nil
}
