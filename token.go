package paseto

import (
	"encoding/json"
	"fmt"
	"time"

	t "aidanwoods.dev/go-result"
)

// Token is a set of paseto claims, and a footer
type Token struct {
	claims map[string]json.RawMessage
	footer []byte
}

func StdDecoder(caf TokenClaimsAndFooter) (*Token, error) {
	return NewTokenFromClaimsJSON(caf.Claims, caf.Footer)
}

// NewToken returns a token with no claims and no footer.
func NewToken() Token {
	return Token{make(map[string]json.RawMessage), nil}
}

func makeToken(claims map[string]json.RawMessage, footer []byte) (*Token, error) {
	tokenValueClaims := make(map[string]json.RawMessage)

	token := Token{tokenValueClaims, footer}

	for key, value := range claims {
		token.claims[key] = value
	}

	return &token, nil
}

// MakeToken allows specifying both claims and a footer.
func MakeToken(claims map[string]interface{}, footer []byte) (*Token, error) {
	tokenValueClaims := make(map[string]json.RawMessage)

	token := Token{tokenValueClaims, footer}

	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return nil, err
		}
	}

	return &token, nil
}

// NewTokenFromClaimsJSON parses the JSON using encoding/json in claimsData
// and returns a token with those claims, and the specified footer.
func NewTokenFromClaimsJSON(claimsData []byte, footer []byte) (*Token, error) {
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(claimsData, &claims); err != nil {
		return nil, err
	}

	return makeToken(claims, footer)
}

// Set sets the key with the specified value. Note that this value needs to
// be serialisable to JSON using encoding/json.
// Set will check this and return an error if it is not serialisable.
func (token *Token) Set(key string, value any) error {
	return t.Chain[any](
		marshalTokenValue(value)).
		AndThen(func(value json.RawMessage) t.Result[any] {
			token.claims[key] = value
			return t.Ok[any](nil)
		}).
		WrapErr("could not set key `" + key + "': %w").
		UnwrapErrOr(nil)
}

func Set[T any](token Token, key string, value T) error {
	return token.Set(key, value)
}

// Get gets the given key and writes the value into output (which should be a
// a pointer), if present by parsing the JSON using encoding/json.
func (t Token) Get(key string, output any) (err error) {
	v, ok := t.claims[key]
	if !ok {
		return fmt.Errorf("value for key `%s' not present in claims", key)
	}

	if err := json.Unmarshal(v, &output); err != nil {
		output = nil
		return err
	}

	return nil
}

func Get[T any](token Token, key string) t.Result[T] {
	var out T
	if err := token.Get(key, &out); err != nil {
		return t.Err[T](err)
	}

	return t.Ok(out)
}

// GetString returns the value for a given key as a string, or error if this
// is not possible (cannot be a string, or value does not exist)
func (t Token) GetString(key string) (string, error) {
	var str string
	if err := t.Get(key, &str); err != nil {
		return "", err
	}

	return str, nil
}

// SetString sets the given key with value. If, for some reason, the provided
// string cannot be serialised as JSON SetString will panic.
func (t *Token) SetString(key string, value string) {
	if err := t.Set(key, value); err != nil {
		// panic if we get an error, we shouldn't fail to encode a string value
		panic(err)
	}
}

// GetTime returns the time for a given key as a string, or error if this
// is not possible (cannot parse as a time, or value does not exist)
func (t Token) GetTime(key string) (time.Time, error) {
	timeStr, err := t.GetString(key)
	if err != nil {
		return time.Time{}, err
	}

	return time.Parse(time.RFC3339, timeStr)
}

// SetTime sets the given key with the given time, encoded using RFC3339 (the
// time format used by common PASETO claims).
func (t *Token) SetTime(key string, value time.Time) {
	t.SetString(key, value.Format(time.RFC3339))
}

// Claims gets the stored claims.
func (t Token) Claims() map[string]interface{} {
	claims := make(map[string]interface{})

	for key, value := range t.claims {
		var claimValue interface{}
		if err := json.Unmarshal(value, &claimValue); err != nil {
			// we only store claims that have gone through json.Marshal
			// it is *very* unexpected if this is not reversable
			panic(err)
		}

		claims[key] = claimValue
	}

	return claims
}

// ClaimsJSON gets the stored claims as JSON.
func (token Token) ClaimsJSON() []byte {
	// these were *just* unmarshalled (and a top level of string keys added)
	// it is *very* unexpected if this is not reversable
	data := t.NewResult(json.Marshal(token.claims)).
		Expect("internal claims data should be well formed JSON")

	return data
}

// Footer returns the token's footer
func (t Token) Footer() []byte {
	return t.footer
}

// SetFooter sets the token's footer
func (t *Token) SetFooter(footer []byte) {
	t.footer = footer
}

func (t Token) encode() TokenClaimsAndFooter {
	return TokenClaimsAndFooter{t.ClaimsJSON(), []byte(t.footer)}
}

// V2Sign signs the token, using the given key.
func (t Token) V2Sign(key V2AsymmetricSecretKey) string {
	return t.encode().V2Sign(key)
}

// V2Encrypt signs the token, using the given key.
func (t Token) V2Encrypt(key V2SymmetricKey) string {
	return t.encode().V2Encrypt(key)
}

// V3Sign signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the signature, but which are not present in
// the final token.
// Implicit must be reprovided for successful verification, and can not be
// recovered.
func (t Token) V3Sign(key V3AsymmetricSecretKey, implicit []byte) string {
	return t.encode().V3Sign(key, implicit)
}

// V3Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (t Token) V3Encrypt(key V3SymmetricKey, implicit []byte) string {
	return t.encode().V3Encrypt(key, implicit)
}

// V4Sign signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the signature, but which are not present in
// the final token.
// Implicit must be reprovided for successful verification, and can not be
// recovered.
func (t Token) V4Sign(key V4AsymmetricSecretKey, implicit []byte) string {
	return t.encode().V4Sign(key, implicit)
}

// V4Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (t Token) V4Encrypt(key V4SymmetricKey, implicit []byte) string {
	return t.encode().V4Encrypt(key, implicit)
}

func newTokenValue(bytes []byte) json.RawMessage {
	return json.RawMessage(bytes)
}

func marshalTokenValue(value interface{}) t.Result[json.RawMessage] {
	return t.Map(t.NewResult(json.Marshal(value)), newTokenValue)
}
