package paseto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSomeString(t *testing.T) {
	token := NewToken()

	err := token.Set("foo", "bar")
	require.NoError(t, err)

	var output string
	err = token.Get("foo", &output)
	require.NoError(t, err)

	require.Equal(t, "bar", output)
}

func TestSomeStruct(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token := NewToken()

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

	token := NewToken()

	err := token.Set("baz", someStruct)
	require.NoError(t, err)

	var output bool
	err = token.Get("baz", &output)
	require.Error(t, err)
}

func TestSomeWrongKey(t *testing.T) {
	token := NewToken()

	err := token.Set("foo", "bar")
	require.NoError(t, err)

	var output string
	err = token.Get("bar", &output)
	require.Error(t, err)
}

func TestFromMap(t *testing.T) {
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

	token, err := MakeToken(
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

	token, err := NewTokenFromClaimsJSON([]byte(data), nil)
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
