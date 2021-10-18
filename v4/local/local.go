package local

import (
	"crypto/rand"
	"hash"
	"io"

	paseto "github.com/aidantwoods/go-paseto"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/salsa20"
)

func Encrypt(p paseto.Packet, key SymmetricKey, implicit []byte) (message paseto.Message, err error) {
	return encrypt(p, key, implicit, nil)
}

func encrypt(p paseto.Packet, key SymmetricKey, implicit []byte, unitTestNonce []byte) (paseto.Message, error) {
	var nonce [32]byte

	if unitTestNonce != nil {
		if len(unitTestNonce) != 32 {
			var m paseto.Message
			return m, errors.New("Unit test nonce incorrect length")
		}

		copy(unitTestNonce, nonce[:])
	}

	io.ReadFull(rand.Reader, nonce[:])

	encKey, authKey, nonce2, err := key.split(nonce)

	if err != nil {
		var m paseto.Message
		return m, err
	}

	var cipherText []byte
	salsa20.XORKeyStream(cipherText, p.Content, nonce2[:], &encKey)

	protocol := paseto.V4Local

	header := []byte(protocol.Header())

	preAuth := paseto.Pae(header, nonce[:], cipherText, p.Footer, implicit)

	var blake hash.Hash

	if blake, err = blake2b.New(32, authKey[:]); err != nil {
		var m paseto.Message
		return m, err
	}

	blake.Write(preAuth)

	var tag [32]byte
	blake.Sum(tag[:])

	message := paseto.Message{
		Protocol: protocol,
		Payload:  Payload{nonce, cipherText, tag},
		Footer:   p.Footer,
	}

	return message, nil
}

// func Decrypt(message paseto.Message, key SymmetricKey, implicit []byte) (packet paseto.Packet, err error) {
// 	protocol := paseto.V4Local

// 	if message.Header() != protocol.Header() {
// 		var p paseto.Packet
// 		return p, errors.Errorf("Cannot decrypt message with header: %s", message.Header())
// 	}

// 	payload, _ := message.Payload.(Payload)

// 	nonce, cipherText, givenTag := payload.nonce, payload.cipherText, payload.tag

// 	encKey, authKey, nonce2, err := key.split(nonce)

// 	if err != nil {
// 		var m paseto.Message
// 		return m, err
// 	}
// }
