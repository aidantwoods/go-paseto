package paseto_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"aidanwoods.dev/go-paseto"
	ty "aidanwoods.dev/go-result"
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
}

func TestV2(t *testing.T) {
	data, err := os.ReadFile("test-vectors/v2.json")
	require.NoError(t, err)

	var tests TestVectors
	err = json.Unmarshal(data, &tests)
	require.NoError(t, err)

	for _, test := range tests.Tests {
		t.Run(test.Name, func(t *testing.T) {
			var decoded ty.Result[paseto.TokenClaimsAndFooter]

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V2SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				message := paseto.NewMessage(paseto.V2Local, test.Token)
				if test.ExpectFail {
					require.Error(t, message.UnwrapErr())
					require.ErrorIs(t, message.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, message.UnwrapErr(), paseto.RuleError{})
					return
				}
				message.Expect("message should be present")

				decoded = paseto.V2LocalDecrypt(message.Unwrap(), sk)
				if test.ExpectFail {
					require.Error(t, decoded.UnwrapErr())
					require.ErrorIs(t, decoded.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, decoded.UnwrapErr(), paseto.RuleError{})
					return
				}
				decoded.Expect("decoded should be present")

			// Public mode
			case "":
				pk, err := paseto.NewV2AsymmetricPublicKeyFromHex(test.PublicKey)
				require.NoError(t, err)

				message := paseto.NewMessage(paseto.V2Public, test.Token)
				if test.ExpectFail {
					require.Error(t, message.UnwrapErr())
					require.ErrorIs(t, message.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, message.UnwrapErr(), paseto.RuleError{})
					return
				}
				message.Expect("message should be present")

				decoded = paseto.V2PublicVerify(message.Unwrap(), pk)
				if test.ExpectFail {
					require.Error(t, decoded.UnwrapErr())
					require.ErrorIs(t, decoded.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, decoded.UnwrapErr(), paseto.RuleError{})
					return
				}
				decoded.Expect("decoded should be present")
			}

			require.Equal(t, test.Payload, string(decoded.Unwrap().Claims))
			require.Equal(t, test.Footer, string(decoded.Unwrap().Footer))

			packet := paseto.NewClaimsAndFooter([]byte(test.Payload), []byte(test.Footer))

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
			var decoded ty.Result[paseto.TokenClaimsAndFooter]

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V3SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				message := paseto.NewMessage(paseto.V3Local, test.Token)
				if test.ExpectFail {
					require.Error(t, message.UnwrapErr())
					require.ErrorIs(t, message.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, message.UnwrapErr(), paseto.RuleError{})
					return
				}
				message.Expect("message should be present")

				decoded = paseto.V3LocalDecrypt(message.Unwrap(), sk, []byte(test.ImplicitAssertation))
				if test.ExpectFail {
					require.Error(t, decoded.UnwrapErr())
					require.ErrorIs(t, decoded.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, decoded.UnwrapErr(), paseto.RuleError{})
					return
				}
				decoded.Expect("decoded should be present")

			// Public mode
			case "":
				pk, err := paseto.NewV3AsymmetricPublicKeyFromHex(test.PublicKey)
				require.NoError(t, err)

				message := paseto.NewMessage(paseto.V3Public, test.Token)
				if test.ExpectFail {
					require.Error(t, message.UnwrapErr())
					require.ErrorIs(t, message.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, message.UnwrapErr(), paseto.RuleError{})
					return
				}
				message.Expect("message should be present")

				decoded = paseto.V3PublicVerify(message.Unwrap(), pk, []byte(test.ImplicitAssertation))
				if test.ExpectFail {
					require.Error(t, decoded.UnwrapErr())
					require.ErrorIs(t, decoded.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, decoded.UnwrapErr(), paseto.RuleError{})
					return
				}
				decoded.Expect("decoded should be present")
			}

			require.Equal(t, test.Payload, string(decoded.Unwrap().Claims))
			require.Equal(t, test.Footer, string(decoded.Unwrap().Footer))

			packet := paseto.NewClaimsAndFooter([]byte(test.Payload), []byte(test.Footer))
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

				decoded = paseto.V3PublicVerify(signed, pk, []byte(test.ImplicitAssertation))
				require.NoError(t, err)

				require.Equal(t, test.Payload, string(decoded.Unwrap().Claims))
				require.Equal(t, test.Footer, string(decoded.Unwrap().Footer))
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
			var decoded ty.Result[paseto.TokenClaimsAndFooter]

			switch test.Key {
			// Local mode
			default:
				sk, err := paseto.V4SymmetricKeyFromHex(test.Key)
				require.NoError(t, err)

				message := paseto.NewMessage(paseto.V4Local, test.Token)
				if test.ExpectFail {
					require.Error(t, message.UnwrapErr())
					require.ErrorIs(t, message.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, message.UnwrapErr(), paseto.RuleError{})
					return
				}
				message.Expect("message should be present")

				decoded = paseto.V4LocalDecrypt(message.Unwrap(), sk, []byte(test.ImplicitAssertation))
				if test.ExpectFail {
					require.Error(t, decoded.UnwrapErr())
					require.ErrorIs(t, decoded.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, decoded.UnwrapErr(), paseto.RuleError{})
					return
				}
				decoded.Expect("decoded should be present")

			// Public mode
			case "":
				pk, err := paseto.NewV4AsymmetricPublicKeyFromHex(test.PublicKey)
				require.NoError(t, err)

				message := paseto.NewMessage(paseto.V4Public, test.Token)
				if test.ExpectFail {
					require.Error(t, message.UnwrapErr())
					require.ErrorIs(t, message.UnwrapErr(), paseto.TokenError{})
					require.NotErrorIs(t, message.UnwrapErr(), paseto.RuleError{})
					return
				}
				message.Expect("message should be present")

				decoded = paseto.V4PublicVerify(message.Unwrap(), pk, []byte(test.ImplicitAssertation))
				if test.ExpectFail {
					require.Error(t, decoded.UnwrapErr())
					// check pointer errors still recognised
					require.ErrorIs(t, decoded.UnwrapErr(), &paseto.TokenError{})
					require.NotErrorIs(t, decoded.UnwrapErr(), &paseto.RuleError{})
					return
				}
				decoded.Expect("decoded should be present")
			}

			require.Equal(t, test.Payload, string(decoded.Unwrap().Claims))
			require.Equal(t, test.Footer, string(decoded.Unwrap().Footer))

			packet := paseto.NewClaimsAndFooter([]byte(test.Payload), []byte(test.Footer))
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
