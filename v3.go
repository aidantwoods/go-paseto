package paseto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"math/big"

	"aidanwoods.dev/go-paseto/internal/encoding"
	"aidanwoods.dev/go-paseto/internal/random"
	"github.com/pkg/errors"
)

func v3PublicSign(packet packet, key V3AsymmetricSecretKey, implicit []byte) message {
	data, footer := packet.content, packet.footer
	header := []byte(V3Public.Header())

	m2 := encoding.Pae(key.Public().compressed(), header, data, footer, implicit)

	hash := sha512.Sum384(m2)

	r, s, err := ecdsa.Sign(rand.Reader, &key.material, hash[:])
	if err != nil {
		panic("Failed to sign")
	}

	var rBytes [48]byte
	var sBytes [48]byte

	r.FillBytes(rBytes[:])
	s.FillBytes(sBytes[:])

	sig := append(rBytes[:], sBytes[:]...)

	if len(sig) != 96 {
		panic("Bad signature length")
	}

	var signature [96]byte
	copy(signature[:], sig)

	return newMessageFromPayload(v3PublicPayload{data, signature}, footer)
}

func v3PublicVerify(msg message, key V3AsymmetricPublicKey, implicit []byte) (packet, error) {
	payload, ok := msg.p.(v3PublicPayload)
	if msg.header() != V3Public.Header() || !ok {
		return packet{}, errors.Errorf("Cannot decrypt message with header: %s", msg.header())
	}

	header, footer := []byte(msg.header()), msg.footer
	data := payload.message

	m2 := encoding.Pae(key.compressed(), header, data, footer, implicit)

	hash := sha512.Sum384(m2)

	r := new(big.Int).SetBytes(payload.signature[:48])
	s := new(big.Int).SetBytes(payload.signature[48:])

	if !ecdsa.Verify(&key.material, hash[:], r, s) {
		return packet{}, errors.Errorf("Bad signature")
	}

	return packet{data, footer}, nil
}

func v3LocalEncrypt(p packet, key V3SymmetricKey, implicit []byte, unitTestNonce []byte) message {
	var nonce [32]byte
	random.UseProvidedOrFillBytes(unitTestNonce, nonce[:])

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

func v3LocalDecrypt(msg message, key V3SymmetricKey, implicit []byte) (packet, error) {
	payload, ok := msg.p.(v3LocalPayload)
	if msg.header() != V3Local.Header() || !ok {
		return packet{}, errors.Errorf("Cannot decrypt message with header: %s", msg.header())
	}

	nonce, cipherText, givenTag := payload.nonce, payload.cipherText, payload.tag
	encKey, authKey, nonce2 := key.split(nonce)

	header := []byte(msg.header())

	preAuth := encoding.Pae(header, nonce[:], cipherText, msg.footer, implicit)

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

	blockCipher, err := aes.NewCipher(encKey[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	plainText := make([]byte, len(cipherText))
	cipher.NewCTR(blockCipher, nonce2[:]).XORKeyStream(plainText, cipherText)

	return packet{plainText, msg.footer}, nil
}
