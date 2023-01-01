package paseto_test

import (
	"testing"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

func TestSomeString(t *testing.T) {
	token := paseto.NewToken()

	err := token.Set("foo", "bar")
	require.NoError(t, err)

	var output string
	err = token.Get("foo", &output)
	require.NoError(t, err)

	require.Equal(t, "bar", output)
}

func TestSomeInt(t *testing.T) {
	token := paseto.NewToken()

	err := token.Set("foo", 3)
	require.NoError(t, err)

	var output string
	err = token.Get("foo", &output)
	require.Error(t, err)
	require.NotErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})

	var intOutput int
	err = token.Get("foo", &intOutput)
	require.NoError(t, err)

	require.Equal(t, 3, intOutput)
}

func TestSomeBool(t *testing.T) {
	token := paseto.NewToken()

	err := token.Set("foo", true)
	require.NoError(t, err)

	var intOutput int
	err = token.Get("foo", &intOutput)
	require.Error(t, err)
	require.NotErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})

	var output bool
	err = token.Get("foo", &output)
	require.NoError(t, err)

	require.Equal(t, true, output)
}

func TestSomeStruct(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token := paseto.NewToken()

	err := token.Set("baz", someStruct)
	require.NoError(t, err)

	var output SomeStruct
	err = token.Get("baz", &output)
	require.NoError(t, err)

	require.Equal(t, someStruct, output)
}

func TestSomeWrongType(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token := paseto.NewToken()

	err := token.Set("baz", someStruct)
	require.NoError(t, err)

	var output bool
	err = token.Get("baz", &output)
	require.Error(t, err)
	require.NotErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})
}

func TestSomeWrongKey(t *testing.T) {
	token := paseto.NewToken()

	err := token.Set("foo", "bar")
	require.NoError(t, err)

	var output string
	err = token.Get("bar", &output)
	require.Error(t, err)
	require.NotErrorIs(t, err, &paseto.RuleError{})
	require.NotErrorIs(t, err, &paseto.TokenError{})
}

func TestFromMap(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token, err := paseto.MakeToken(
		map[string]interface{}{
			"foo": "bar",
			"baz": someStruct,
		},
		nil,
	)
	require.NoError(t, err)

	var outputStr string
	err = token.Get("foo", &outputStr)
	require.NoError(t, err)

	require.Equal(t, "bar", outputStr)

	var outputStruct SomeStruct
	err = token.Get("baz", &outputStruct)
	require.NoError(t, err)

	require.Equal(t, someStruct, outputStruct)
}

func TestJsonEncode(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token, err := paseto.MakeToken(
		map[string]interface{}{
			"foo": "bar",
			"baz": someStruct,
		},
		nil,
	)
	require.NoError(t, err)

	require.JSONEq(t,
		`{"foo":"bar","baz":{"Field1":"boo","Field2":3,"Field3":true}}`,
		string(token.ClaimsJSON()),
	)
}

func TestJsonParse(t *testing.T) {
	data := `{"foo":"bar","baz":{"Field1":"boo","Field2":3,"Field3":true}}`

	token, err := paseto.NewTokenFromClaimsJSON([]byte(data), nil)
	require.NoError(t, err)

	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	var outputStr string
	err = token.Get("foo", &outputStr)
	require.NoError(t, err)

	expectedStr := "bar"
	require.Equal(t, expectedStr, outputStr)

	var outputStruct SomeStruct
	err = token.Get("baz", &outputStruct)
	require.NoError(t, err)

	expectedStruct := SomeStruct{"boo", 3, true}
	require.Equal(t, expectedStruct, outputStruct)

	require.JSONEq(t, data, string(token.ClaimsJSON()))
}

func TestSignSelfConsistent(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token, err := paseto.MakeToken(
		map[string]interface{}{
			"foo": "bar",
			"baz": someStruct,
		},
		nil,
	)
	require.NoError(t, err)

	parser := paseto.NewParserWithoutExpiryCheck()

	key := paseto.NewV4AsymmetricSecretKey()

	signed := token.V4Sign(key, nil)

	verifiedToken, err := parser.ParseV4Public(key.Public(), signed, nil)
	require.NoError(t, err)

	originalClaims := token.ClaimsJSON()
	require.NoError(t, err)
	verifiedClaims := verifiedToken.ClaimsJSON()
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

	token, err := paseto.MakeToken(
		map[string]interface{}{
			"foo": "bar",
			"baz": someStruct,
		},
		nil,
	)
	require.NoError(t, err)

	parser := paseto.NewParserWithoutExpiryCheck()

	key := paseto.NewV4SymmetricKey()

	encrypted := token.V4Encrypt(key, nil)

	verifiedToken, err := parser.ParseV4Local(key, encrypted, nil)
	require.NoError(t, err)

	originalClaims := token.ClaimsJSON()
	verifiedClaims := verifiedToken.ClaimsJSON()

	require.JSONEq(t, string(originalClaims), string(verifiedClaims))
}

func TestReadmePublicExample(t *testing.T) {
	publicKey, _ := paseto.NewV4AsymmetricPublicKeyFromHex("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	signed := "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"

	parser := paseto.NewParserWithoutExpiryCheck()

	token, err := parser.ParseV4Public(publicKey, signed, nil)
	require.NoError(t, err)

	claimsJSON := token.ClaimsJSON()

	require.JSONEq(t,
		"{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
		string(claimsJSON),
	)
	require.Equal(t,
		"{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
		string(token.Footer()),
	)
}
