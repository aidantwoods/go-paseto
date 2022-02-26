package paseto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSomeString(t *testing.T) {
	token := NewEmptyToken([]Version{Version4})

	token.Set("foo", "bar")

	var output string
	err, exists := token.Get("foo", &output)
	require.NoError(t, err)
	require.True(t, exists)

	require.Equal(t, "bar", output)
}

func TestSomeStruct(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token := NewEmptyToken([]Version{Version4})

	token.Set("baz", someStruct)

	var output SomeStruct
	err, exists := token.Get("baz", &output)
	require.NoError(t, err)
	require.True(t, exists)

	require.Equal(t, someStruct, output)
}

func TestSomeWrongType(t *testing.T) {
	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	someStruct := SomeStruct{"boo", 3, true}

	token := NewEmptyToken([]Version{Version4})

	token.Set("baz", someStruct)

	var output bool
	err, exists := token.Get("baz", &output)
	require.Error(t, err)
	require.True(t, exists)
}

func TestSomeWrongKey(t *testing.T) {
	token := NewEmptyToken([]Version{Version4})

	token.Set("foo", "bar")

	var output string
	err, exists := token.Get("bar", &output)
	require.Error(t, err)
	require.False(t, exists)
}

func TestFromMap(t *testing.T) {
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
		"",
		[]Version{Version4},
	)

	var outputStr string
	err, exists := token.Get("foo", &outputStr)
	require.NoError(t, err)
	require.True(t, exists)

	require.Equal(t, "bar", outputStr)

	var outputStruct SomeStruct
	err, exists = token.Get("baz", &outputStruct)
	require.NoError(t, err)
	require.True(t, exists)

	require.Equal(t, someStruct, outputStruct)
}

func TestJsonEncode(t *testing.T) {
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
		"",
		[]Version{Version4},
	)

	data, err := token.ClaimsJson()
	require.NoError(t, err)

	expected := `{"foo":"bar","baz":{"Field1":"boo","Field2":3,"Field3":true}}`

	require.JSONEq(t, expected, string(data))
}

func TestJsonParse(t *testing.T) {
	data := `{"foo":"bar","baz":{"Field1":"boo","Field2":3,"Field3":true}}`

	token, err := NewTokenFromClaimsJson([]byte(data), "", []Version{Version4})
	require.NoError(t, err)

	type SomeStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	var outputStr string
	err, exists := token.Get("foo", &outputStr)
	require.NoError(t, err)
	require.True(t, exists)

	expectedStr := "bar"
	require.Equal(t, expectedStr, outputStr)

	var outputStruct SomeStruct
	err, exists = token.Get("baz", &outputStruct)
	require.NoError(t, err)
	require.True(t, exists)

	expectedStruct := SomeStruct{"boo", 3, true}
	require.Equal(t, expectedStruct, outputStruct)

	encodedData, err := token.ClaimsJson()
	require.NoError(t, err)

	require.JSONEq(t, data, string(encodedData))
}
