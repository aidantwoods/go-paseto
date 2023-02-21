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
	t "aidanwoods.dev/go-result"
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

	return newMessageFromPayloadAndFooter(v3PublicPayload{data, signature}, footer)
}

func v3PublicVerify(msg message, key V3AsymmetricPublicKey, implicit []byte) t.Result[packet] {
	payload, ok := msg.p.(v3PublicPayload)
	if msg.header() != V3Public.Header() || !ok {
		return t.Err[packet](errorMessageHeaderVerify(V3Public, msg.header()))
	}

	header, footer := []byte(msg.header()), msg.footer
	data := payload.message

	m2 := encoding.Pae(key.compressed(), header, data, footer, implicit)

	hash := sha512.Sum384(m2)

	r := new(big.Int).SetBytes(payload.signature[:48])
	s := new(big.Int).SetBytes(payload.signature[48:])

	if !ecdsa.Verify(&key.material, hash[:], r, s) {
		return t.Err[packet](errorBadSignature)
	}

	return t.Ok(packet{data, footer})
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

	return newMessageFromPayloadAndFooter(v3LocalPayload{nonce, cipherText, tag}, p.footer)
}

func v3LocalDecrypt(msg message, key V3SymmetricKey, implicit []byte) t.Result[packet] {
	payload, ok := msg.p.(v3LocalPayload)
	if msg.header() != V3Local.Header() || !ok {
		return t.Err[packet](errorMessageHeaderDecrypt(V3Local, msg.header()))
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
		return t.Err[packet](errorBadMAC)
	}

	blockCipher, err := aes.NewCipher(encKey[:])
	if err != nil {
		panic("Cannot construct cipher")
	}

	plainText := make([]byte, len(cipherText))
	cipher.NewCTR(blockCipher, nonce2[:]).XORKeyStream(plainText, cipherText)

	return t.Ok(packet{plainText, msg.footer})
}
