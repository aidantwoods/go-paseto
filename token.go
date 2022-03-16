package paseto

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

// Token is a set of paseto claims, and a footer
type Token struct {
	claims map[string]tokenValue
	footer []byte
}

// NewToken returns a token with no claims and no footer.
func NewToken() Token {
	return Token{make(map[string]tokenValue), nil}
}

// MakeToken allows specifying both claims and a footer.
func MakeToken(claims map[string]interface{}, footer []byte) (*Token, error) {
	tokenValueClaims := make(map[string]tokenValue)

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
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsData, &claims); err != nil {
		return nil, err
	}

	return MakeToken(claims, footer)
}

// Set sets the key with the specified value. Note that this value needs to
// be serialisable to JSON using encoding/json.
// Set will check this and return an error if it is not serialisable.
func (t *Token) Set(key string, value interface{}) error {
	v, err := newTokenValue(value)
	if err != nil {
		return errors.Wrapf(err, "could not set key `%s`", key)
	}

	t.claims[key] = *v

	return nil
}

// Get gets the given key and writes the value into output (which should be a
// a pointer), if present by parsing the JSON using encoding/json.
func (t Token) Get(key string, output interface{}) (err error) {
	v, ok := t.claims[key]
	if !ok {
		return errors.Errorf("value for key `%s' not present in claims", key)
	}

	if err := json.Unmarshal(v.rawValue, &output); err != nil {
		output = nil
		return err
	}

	return nil
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
		if err := json.Unmarshal(value.rawValue, &claimValue); err != nil {
			// we only store claims that have gone through json.Marshal
			// it is *very* unexpected if this is not reversable
			panic(err)
		}

		claims[key] = claimValue
	}

	return claims
}

// ClaimsJSON gets the stored claims as JSON.
func (t Token) ClaimsJSON() []byte {
	data, err := json.Marshal(t.Claims())
	if err != nil {
		// these were *just* unmarshalled (and a top level of string keys added)
		// it is *very* unexpected if this is not reversable
		panic(err)
	}

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

func (t Token) packet() packet {
	return packet{t.ClaimsJSON(), []byte(t.footer)}
}

// V2Sign signs the token, using the given key.
func (t Token) V2Sign(key V2AsymmetricSecretKey) string {
	return v2PublicSign(t.packet(), key).encoded()
}

// V2Encrypt signs the token, using the given key.
func (t Token) V2Encrypt(key V2SymmetricKey) string {
	return v2LocalEncrypt(t.packet(), key, nil).encoded()
}

// V3Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (t Token) V3Encrypt(key V3SymmetricKey, implicit []byte) string {
	return v3LocalEncrypt(t.packet(), key, implicit, nil).encoded()
}

// V4Sign signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the signature, but which are not present in
// the final token.
// Implicit must be reprovided for successful verification, and can not be
// recovered.
func (t Token) V4Sign(key V4AsymmetricSecretKey, implicit []byte) string {
	return v4PublicSign(t.packet(), key, implicit).encoded()
}

// V4Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (t Token) V4Encrypt(key V4SymmetricKey, implicit []byte) string {
	return v4LocalEncrypt(t.packet(), key, implicit, nil).encoded()
}

type tokenValue struct {
	// we store the encoded value, and let json.Unmarshal take care of
	// conversion
	rawValue []byte
}

func newTokenValue(value interface{}) (*tokenValue, error) {
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	return &tokenValue{bytes}, nil
}
