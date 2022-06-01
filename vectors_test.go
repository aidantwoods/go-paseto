package paseto_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
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
	Paserk              string
	Comment             string
}

func TestV2(t *testing.T) {
	data, err := os.ReadFile("test-vectors/v2.json")
	require.NoError(t, err)

	var tests TestVectors
	err = json.Unmarshal(data, &tests)
	require.NoError(t, err)

	for _, test := range tests.Tests {
		t.Run(test.Name, func(t *testing.T) {
			var decoded paseto.Packet

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V2SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				message, err := paseto.NewMessage(paseto.V2Local, test.Token)
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				decoded, err = paseto.V2LocalDecrypt(message, sk)
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

			// Public mode
			case "":
				pk, err := paseto.NewV2AsymmetricPublicKeyFromHex(test.PublicKey)
				require.NoError(t, err)

				message, err := paseto.NewMessage(paseto.V2Public, test.Token)
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				decoded, err = paseto.V2PublicVerify(message, pk)
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
			}

			require.Equal(t, test.Payload, string(decoded.Content()))
			require.Equal(t, test.Footer, string(decoded.Footer()))

			packet := paseto.NewPacket([]byte(test.Payload), []byte(test.Footer))

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V2SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				unitTestNonce, err := hex.DecodeString(test.Nonce)
				require.NoError(t, err)

				encrypted := paseto.V2LocalEncrypt(packet, sk, unitTestNonce)
				require.NoError(t, err)

				require.Equal(t, test.Token, encrypted.Encoded())

			// Public mode
			case "":
				sk, err := paseto.NewV2AsymmetricSecretKeyFromHex(test.SecretKey)
				require.NoError(t, err)

				signed := paseto.V2PublicSign(packet, sk)
				require.NoError(t, err)

				require.Equal(t, test.Token, signed.Encoded())
			}
		})
	}
}

func TestV3(t *testing.T) {
	data, err := os.ReadFile("test-vectors/v3.json")
	require.NoError(t, err)

	var tests TestVectors
	err = json.Unmarshal(data, &tests)
	require.NoError(t, err)

	for _, test := range tests.Tests {
		t.Run(test.Name, func(t *testing.T) {
			var decoded paseto.Packet

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V3SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				message, err := paseto.NewMessage(paseto.V3Local, test.Token)
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				decoded, err = paseto.V3LocalDecrypt(message, sk, []byte(test.ImplicitAssertation))
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

			// Public mode
			case "":
				pk, err := paseto.NewV3AsymmetricPublicKeyFromHex(test.PublicKey)
				require.NoError(t, err)

				message, err := paseto.NewMessage(paseto.V3Public, test.Token)
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				decoded, err = paseto.V3PublicVerify(message, pk, []byte(test.ImplicitAssertation))
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
			}

			require.Equal(t, test.Payload, string(decoded.Content()))
			require.Equal(t, test.Footer, string(decoded.Footer()))

			packet := paseto.NewPacket([]byte(test.Payload), []byte(test.Footer))
			implicit := []byte(test.ImplicitAssertation)

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V3SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				unitTestNonce, err := hex.DecodeString(test.Nonce)
				require.NoError(t, err)

				encrypted := paseto.V3LocalEncrypt(packet, sk, implicit, unitTestNonce)
				require.NoError(t, err)

				require.Equal(t, test.Token, encrypted.Encoded())

			// Public mode
			case "":
				sk, err := paseto.NewV3AsymmetricSecretKeyFromHex(test.SecretKey)
				require.NoError(t, err)

				signed := paseto.V3PublicSign(packet, sk, implicit)

				// v3 signatures are not deterministic in this implementation, so just check that something signed can be verified

				pk, err := paseto.NewV3AsymmetricPublicKeyFromHex(test.PublicKey)
				require.NoError(t, err)

				decoded, err = paseto.V3PublicVerify(signed, pk, []byte(test.ImplicitAssertation))
				require.NoError(t, err)

				require.Equal(t, test.Payload, string(decoded.Content()))
				require.Equal(t, test.Footer, string(decoded.Footer()))
			}
		})
	}
}

func TestV3SigLenIncorrect(t *testing.T) {
	for i := 0; i < 100; i++ {
		t.Run(fmt.Sprintf("V3 run %d", i), TestV3)
	}
}

func TestV4(t *testing.T) {
	data, err := os.ReadFile("test-vectors/v4.json")
	require.NoError(t, err)

	var tests TestVectors
	err = json.Unmarshal(data, &tests)
	require.NoError(t, err)

	for _, test := range tests.Tests {
		t.Run(test.Name, func(t *testing.T) {
			var decoded paseto.Packet

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V4SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				message, err := paseto.NewMessage(paseto.V4Local, test.Token)
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				decoded, err = paseto.V4LocalDecrypt(message, sk, []byte(test.ImplicitAssertation))
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

			// Public mode
			case "":
				pk, err := paseto.NewV4AsymmetricPublicKeyFromHex(test.PublicKey)
				require.NoError(t, err)

				message, err := paseto.NewMessage(paseto.V4Public, test.Token)
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				decoded, err = paseto.V4PublicVerify(message, pk, []byte(test.ImplicitAssertation))
				if test.ExpectFail {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
			}

			require.Equal(t, test.Payload, string(decoded.Content()))
			require.Equal(t, test.Footer, string(decoded.Footer()))

			packet := paseto.NewPacket([]byte(test.Payload), []byte(test.Footer))
			implicit := []byte(test.ImplicitAssertation)

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V4SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				unitTestNonce, err := hex.DecodeString(test.Nonce)
				require.NoError(t, err)

				encrypted := paseto.V4LocalEncrypt(packet, sk, implicit, unitTestNonce)
				require.NoError(t, err)

				require.Equal(t, test.Token, encrypted.Encoded())

			// Public mode
			case "":
				sk, err := paseto.NewV4AsymmetricSecretKeyFromHex(test.SecretKey)
				require.NoError(t, err)

				signed := paseto.V4PublicSign(packet, sk, implicit)
				require.NoError(t, err)

				require.Equal(t, test.Token, signed.Encoded())
			}
		})
	}
}

func TestPaserkV4Public(t *testing.T) {
	data, err := os.ReadFile("test-vectors/PASERK/k4.public.json")
	require.NoError(t, err)

	var tests TestVectors
	err = json.Unmarshal(data, &tests)
	require.NoError(t, err)

	for _, test := range tests.Tests {
		t.Run(test.Name, func(t *testing.T) {

			k, err := paseto.NewV4AsymmetricPublicKeyFromHex(test.Key)
			if test.ExpectFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			token, err := k.ExportPaserk(paseto.PaserkTypePublic)
			if test.ExpectFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, test.Paserk, token)
		})
	}

	for _, test := range tests.Tests {
		t.Run(test.Name+"-reverse", func(t *testing.T) {

			k, err := paseto.ParsePaserkRaw(test.Paserk)
			if test.ExpectFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			v4key := k.(*paseto.V4AsymmetricPublicKey)
			require.Equal(t, test.Key, v4key.ExportHex())
		})
	}
}
