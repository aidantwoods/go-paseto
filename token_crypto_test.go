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

	originalClaims, err := token.ClaimsJSON()
	require.NoError(t, err)
	verifiedClaims, err := verifiedToken.ClaimsJSON()
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

	originalClaims, err := token.ClaimsJSON()
	require.NoError(t, err)
	verifiedClaims, err := verifiedToken.ClaimsJSON()
	require.NoError(t, err)

	require.JSONEq(t, string(originalClaims), string(verifiedClaims))
}

func TestReadmePublicExample(t *testing.T) {
	publicKey, _ := NewV4AsymmetricPublicKeyFromHex("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	signed := "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"

	parser := NewParser()

	token, err := parser.ParseV4Public(publicKey, signed, nil)
	require.NoError(t, err)

	claimsJSON, err := token.ClaimsJSON()
	require.NoError(t, err)

	require.JSONEq(t,
		"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
		string(claimsJSON),
	)
	require.Equal(t,
		"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
		string(token.Footer()),
	)
}
