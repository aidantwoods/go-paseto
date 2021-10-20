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
		if test.Key == "" {
			// skip public mode for now
			t.Logf("Skipping %s...", test.Name)
			continue
		}

		t.Run(test.Name, func(t *testing.T) {
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

			var decrypted Packet
			if decrypted, err = V4LocalDecrypt(message, sk, []byte(test.ImplicitAssertation)); err != nil {
				if test.ExpectFail {
					return
				}

				t.Error(err)
				return
			}

			if test.Payload != string(decrypted.Content) {
				t.Errorf("Expected: %s, got: %s", test.Payload, decrypted.Content)
			}

			if test.Footer != string(decrypted.Footer) {
				t.Errorf("Expected: %s, got: %s", test.Footer, decrypted.Footer)
			}

			var unitTestNonce []byte
			if unitTestNonce, err = hex.DecodeString(test.Nonce); err != nil {
				t.Error(err)
				return
			}

			packet := NewPacket([]byte(test.Payload), []byte(test.Footer))
			implicit := []byte(test.ImplicitAssertation)

			var encrypted Message
			if encrypted, err = v4LocalEncrypt(packet, sk, implicit, unitTestNonce); err != nil {
				t.Error(err)
				return
			}

			if encrypted.Encoded() != test.Token {
				t.Errorf("Expected: %s, got: %s", test.Token, encrypted.Encoded())
			}
		})
	}
}
