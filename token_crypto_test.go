package paseto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignSelfConsistent(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token, err := MakeToken(
		map[string]interface{}{
			"foo": "bar",
			"baz": someStruct,
		},
		nil,
	)
	require.NoError(t, err)

	parser := MakeParser(nil)

	key := NewV4AsymmetricSecretKey()

	signed, err := token.V4Sign(key, nil)
	require.NoError(t, err)
	require.NotNil(t, signed)

	verifiedToken, err := parser.ParseV4Public(key.Public(), *signed, nil)
	require.NoError(t, err)

	originalClaims, err := token.ClaimsJson()
	require.NoError(t, err)
	verifiedClaims, err := verifiedToken.ClaimsJson()
	require.NoError(t, err)

	require.JSONEq(t, string(originalClaims), string(verifiedClaims))
}

func TestEncryptSelfConsistent(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token, err := MakeToken(
		map[string]interface{}{
			"foo": "bar",
			"baz": someStruct,
		},
		nil,
	)
	require.NoError(t, err)

	parser := MakeParser(nil)

	key := NewV4SymmetricKey()

	encrypted, err := token.V4Encrypt(key, nil)
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	verifiedToken, err := parser.ParseV4Local(key, *encrypted, nil)
	require.NoError(t, err)

	originalClaims, err := token.ClaimsJson()
	require.NoError(t, err)
	verifiedClaims, err := verifiedToken.ClaimsJson()
	require.NoError(t, err)

	require.JSONEq(t, string(originalClaims), string(verifiedClaims))
}
