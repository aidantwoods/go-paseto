package paseto

import (
	"crypto/ed25519"

	"aidanwoods.dev/go-paseto/internal/encoding"
	"aidanwoods.dev/go-paseto/internal/hashing"
	"aidanwoods.dev/go-paseto/internal/random"
	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

func v2PublicSign(packet packet, key V2AsymmetricSecretKey) message {
	data, footer := packet.content, packet.footer
	header := []byte(V2Public.Header())

	m2 := encoding.Pae(header, data, footer)

	sig := ed25519.Sign(key.material, m2)

	if len(sig) != 64 {
		panic("Bad signature length")
	}

	var signature [64]byte
	copy(signature[:], sig)

	return newMessageFromPayload(v2PublicPayload{data, signature}, footer)
}

func v2PublicVerify(msg message, key V2AsymmetricPublicKey) (packet, error) {
	payload, ok := msg.p.(v2PublicPayload)
	if msg.header() != V2Public.Header() || !ok {
		return packet{}, errors.Errorf("Cannot decrypt message with header: %s", msg.header())
	}

	header, footer := []byte(msg.header()), msg.footer
	data := payload.message

	m2 := encoding.Pae(header, data, footer)

	if !ed25519.Verify(key.material, m2, payload.signature[:]) {
		return packet{}, errors.Errorf("Bad signature")
	}

	return packet{data, footer}, nil
}

func v2LocalEncrypt(p packet, key V2SymmetricKey, unitTestNonce []byte) message {
	var b [24]byte
	random.UseProvidedOrFillBytes(unitTestNonce, b[:])

	var nonce [24]byte
	hashing.GenericHash(p.content, nonce[:], b[:])

	cipher, err := chacha20poly1305.NewX(key.material[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	header := []byte(V2Local.Header())

	preAuth := encoding.Pae(header, nonce[:], p.footer)

	cipherText := cipher.Seal(nil, nonce[:], p.content, preAuth)

	return newMessageFromPayload(v2LocalPayload{nonce, cipherText}, p.footer)
}

func v2LocalDecrypt(msg message, key V2SymmetricKey) (packet, error) {
	payload, ok := msg.p.(v2LocalPayload)
	if msg.header() != V2Local.Header() || !ok {
		return packet{}, errors.Errorf("Cannot decrypt message with header: %s", msg.header())
	}

	nonce, cipherText := payload.nonce, payload.cipherText

	header := []byte(msg.header())

	preAuth := encoding.Pae(header, nonce[:], msg.footer)

	cipher, err := chacha20poly1305.NewX(key.material[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	plainText, err := cipher.Open(nil, nonce[:], cipherText, preAuth)
	if err != nil {
		return packet{}, errors.Errorf("The message could not be decrypted. %s", err)
	}

	return packet{plainText, msg.footer}, nil
}
