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

	token, err := NewToken(
		map[string]interface{}{
			"foo": "bar",
			"baz": someStruct,
		},
		nil,
	)
	require.NoError(t, err)

	key := NewV4AsymmetricSecretKey()

	message, err := token.V4Sign(key, nil)
	require.NoError(t, err)
	require.NotNil(t, message)

	verifiedToken, err := message.V4Verify(key.Public(), nil)
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

	token, err := NewToken(
		map[string]interface{}{
			"foo": "bar",
			"baz": someStruct,
		},
		nil,
	)
	require.NoError(t, err)

	key := NewV4SymmetricKey()

	message, err := token.V4Encrypt(key, nil)
	require.NoError(t, err)
	require.NotNil(t, message)

	verifiedToken, err := message.V4Decrypt(key, nil)
	require.NoError(t, err)

	originalClaims, err := token.ClaimsJson()
	require.NoError(t, err)
	verifiedClaims, err := verifiedToken.ClaimsJson()
	require.NoError(t, err)

	require.JSONEq(t, string(originalClaims), string(verifiedClaims))
}
