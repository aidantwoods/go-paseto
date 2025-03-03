package paserk

import (
	"encoding/json"
	"os"
	"testing"

	"aidanwoods.dev/go-paseto/v2"
	"github.com/stretchr/testify/require"
)

type TestVectors struct {
	Name  string
	Tests []TestVector
}

type TestVector struct {
	Name       string
	Key        string
	Paserk     string
	ExpectFail bool `json:"expect-fail"`
	Comment    string
}

func TestKID(t *testing.T) {
	testKID(t, paseto.V2SymmetricKeyFromHex, "../test-vectors/PASERK/k2.lid.json")
	testKID(t, paseto.NewV2AsymmetricSecretKeyFromHex, "../test-vectors/PASERK/k2.sid.json")
	testKID(t, paseto.NewV2AsymmetricPublicKeyFromHex, "../test-vectors/PASERK/k2.pid.json")
	testKID(t, paseto.V3SymmetricKeyFromHex, "../test-vectors/PASERK/k3.lid.json")
	testKID(t, paseto.NewV3AsymmetricSecretKeyFromHex, "../test-vectors/PASERK/k3.sid.json")
	testKID(t, paseto.NewV3AsymmetricPublicKeyFromHex, "../test-vectors/PASERK/k3.pid.json")
	testKID(t, paseto.V4SymmetricKeyFromHex, "../test-vectors/PASERK/k4.lid.json")
	testKID(t, paseto.NewV4AsymmetricSecretKeyFromHex, "../test-vectors/PASERK/k4.sid.json")
	testKID(t, paseto.NewV4AsymmetricPublicKeyFromHex, "../test-vectors/PASERK/k4.pid.json")
}

type keyLoader[T Key] func(hexEncoded string) (T, error)

func testKID[T Key](t *testing.T, loader keyLoader[T], path string) {
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var tests TestVectors
	err = json.Unmarshal(data, &tests)
	require.NoError(t, err)

	for _, test := range tests.Tests {
		t.Run(test.Name, func(t *testing.T) {
			key, err := loader(test.Key)
			if test.ExpectFail {
				require.Error(t, err)
				return
			}

			kid, err := SerializeKeyID(key)
			require.NoError(t, err)
			require.Equal(t, test.Paserk, kid)
		})
	}
}

func TestSerialization(t *testing.T) {
	testSerialization(t, paseto.V2SymmetricKeyFromHex, "../test-vectors/PASERK/k2.local.json")
	testSerialization(t, paseto.NewV2AsymmetricSecretKeyFromHex, "../test-vectors/PASERK/k2.secret.json")
	testSerialization(t, paseto.NewV2AsymmetricPublicKeyFromHex, "../test-vectors/PASERK/k2.public.json")
	testSerialization(t, paseto.V3SymmetricKeyFromHex, "../test-vectors/PASERK/k3.local.json")
	testSerialization(t, paseto.NewV3AsymmetricSecretKeyFromHex, "../test-vectors/PASERK/k3.secret.json")
	testSerialization(t, paseto.NewV3AsymmetricPublicKeyFromHex, "../test-vectors/PASERK/k3.public.json")
	testSerialization(t, paseto.V4SymmetricKeyFromHex, "../test-vectors/PASERK/k4.local.json")
	testSerialization(t, paseto.NewV4AsymmetricSecretKeyFromHex, "../test-vectors/PASERK/k4.secret.json")
	testSerialization(t, paseto.NewV4AsymmetricPublicKeyFromHex, "../test-vectors/PASERK/k4.public.json")
}

func testSerialization[T Key](t *testing.T, loader keyLoader[T], path string) {
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var tests TestVectors
	err = json.Unmarshal(data, &tests)
	require.NoError(t, err)

	for _, test := range tests.Tests {
		t.Run(test.Name, func(t *testing.T) {
			deserialized, err := DeserializeKey[T](test.Paserk)
			if test.ExpectFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			key, err := loader(test.Key)
			require.NoError(t, err)
			require.Equal(t, key, deserialized)

			paserk, err := SerializeKey(key)
			require.NoError(t, err)
			require.Equal(t, test.Paserk, paserk)
		})
	}
}
