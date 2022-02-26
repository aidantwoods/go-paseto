package paseto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type TestVectors struct {
	Name  string
	Tests []TestVector
}

type TestVector struct {
	Name                string
	Nonce               string
	Key                 string
	PublicKey           string `json:"public-key"`
	SecretKey           string `json:"secret-key"`
	Token               string
	Payload             string
	Footer              string
	ExpectFail          bool   `json:"expect-fail"`
	ImplicitAssertation string `json:"implicit-assertion"`
}

func TestV4(t *testing.T) {
	data, err := os.ReadFile("test-vectors/v4.json")
	if err != nil {
		t.Errorf("Error reading file: %s", err)
	}

	var tests TestVectors
	err = json.Unmarshal(data, &tests)
	if err != nil {
		t.Errorf("Error reading file: %s", err)
	}

	for _, test := range tests.Tests {
		t.Run(test.Name, func(t *testing.T) {
			var decoded Packet

			switch test.Key {
			// Local mode
			default:
				var sk V4SymmetricKey
				if sk, err = V4SymmetricKeyFromHex(test.Key); err != nil {
					t.Error(err)
					return
				}

				var message Message
				if message, err = NewMessage(V4Local, test.Token); err != nil {
					if test.ExpectFail {
						return
					}

					t.Error(err)
					return
				}

				if decoded, err = V4LocalDecrypt(message, sk, []byte(test.ImplicitAssertation)); err != nil {
					if test.ExpectFail {
						return
					}

					t.Error(err)
					return
				}
			// Public mode
			case "":
				var pk V4AsymmetricPublicKey

				if pk, err = NewV4AsymmetricPublicKeyFromHex(test.PublicKey); err != nil {
					t.Error(err)
					return
				}

				var message Message
				if message, err = NewMessage(V4Public, test.Token); err != nil {
					if test.ExpectFail {
						return
					}

					t.Error(err)
					return
				}

				if decoded, err = V4PublicVerify(message, pk, []byte(test.ImplicitAssertation)); err != nil {
					if test.ExpectFail {
						return
					}

					t.Error(err)
					return
				}
			}

			if test.Payload != string(decoded.Content) {
				t.Errorf("Expected: %s, got: %s", test.Payload, decoded.Content)
			}

			if test.Footer != string(decoded.Footer) {
				t.Errorf("Expected: %s, got: %s", test.Footer, decoded.Footer)
			}

			packet := NewPacket([]byte(test.Payload), []byte(test.Footer))
			implicit := []byte(test.ImplicitAssertation)

			switch test.Key {
			// Local mode
			default:
				var sk V4SymmetricKey
				if sk, err = V4SymmetricKeyFromHex(test.Key); err != nil {
					t.Error(err)
					return
				}

				var unitTestNonce []byte
				if unitTestNonce, err = hex.DecodeString(test.Nonce); err != nil {
					t.Error(err)
					return
				}

				var encrypted Message
				if encrypted = v4LocalEncrypt(packet, sk, implicit, unitTestNonce); err != nil {
					t.Error(err)
					return
				}

				if encrypted.Encoded() != test.Token {
					t.Errorf("Expected: %s, got: %s", test.Token, encrypted.Encoded())
				}
			// Public mode
			case "":
				var sk V4AsymmetricSecretKey
				if sk, err = NewV4AsymmetricSecretKeyFromHex(test.SecretKey); err != nil {
					t.Error(err)
					return
				}

				var signed Message
				if signed = V4PublicSign(packet, sk, implicit); err != nil {
					t.Error(err)
					return
				}

				if signed.Encoded() != test.Token {
					t.Errorf("Expected: %s, got: %s", test.Token, signed.Encoded())
				}
			}
		})
	}
}
