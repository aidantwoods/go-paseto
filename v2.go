package paseto

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"

	"github.com/aidantwoods/go-paseto/internal/encoding"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

func v2PublicSign(packet packet, key V2AsymmetricSecretKey) Message {
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

func v2PublicVerify(message Message, key V2AsymmetricPublicKey) (packet, error) {
	var payload v2PublicPayload
	var ok bool

	if payload, ok = message.p.(v2PublicPayload); message.Header() != V2Public.Header() || !ok {
		var p packet
		return p, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
	}

	header, footer := []byte(message.Header()), message.footer
	data := payload.message

	m2 := encoding.Pae(header, data, footer)

	if !ed25519.Verify(key.material, m2, payload.signature[:]) {
		var p packet
		return p, errors.Errorf("Bad signature")
	}

	return packet{data, footer}, nil
}

func v2LocalEncrypt(p packet, key V2SymmetricKey, unitTestNonce []byte) Message {
	var b [24]byte

	if unitTestNonce != nil {
		if len(unitTestNonce) != 24 {
			panic("Unit test nonce incorrect length")
		}

		copy(b[:], unitTestNonce)
	} else {
		_, err := io.ReadFull(rand.Reader, b[:])

		if err != nil {
			panic("CSPRNG failure")
		}
	}

	blake, err := blake2b.New(24, b[:])
	if err != nil {
		panic("Cannot construct hash")
	}
	if _, err = blake.Write(p.content); err != nil {
		panic("Cannot write to hash")
	}

	var nonce [24]byte
	copy(nonce[:], blake.Sum(nil))

	cipher, err := chacha20poly1305.NewX(key.material[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	header := []byte(V2Local.Header())

	preAuth := encoding.Pae(header, nonce[:], p.footer)

	cipherText := cipher.Seal(nil, nonce[:], p.content, preAuth)

	return newMessageFromPayload(v2LocalPayload{nonce, cipherText}, p.footer)
}

func v2LocalDecrypt(message Message, key V2SymmetricKey) (packet, error) {
	var payload v2LocalPayload
	var ok bool

	if payload, ok = message.p.(v2LocalPayload); message.Header() != V2Local.Header() || !ok {
		var p packet
		return p, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
	}

	nonce, cipherText := payload.nonce, payload.cipherText

	cipher, err := chacha20poly1305.NewX(key.material[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	header := []byte(message.Header())

	preAuth := encoding.Pae(header, nonce[:], message.footer)

	plainText, err := cipher.Open(nil, nonce[:], cipherText, preAuth)
	if err != nil {
		var p packet
		return p, errors.Errorf("The message could not be decrypted. %s", err)
	}

	return packet{plainText, message.footer}, nil
}
