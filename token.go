package paseto

import (
	"encoding/json"

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
	var err error

	if err = json.Unmarshal(claimsData, &claims); err != nil {
		return nil, err
	}

	return MakeToken(claims, footer)
}

// Set sets the key with the specified value. Note that this value needs to
// be serialisable to JSON using encoding/json.
// Set will check this and return an error if it is not serialisable.
func (t *Token) Set(key string, value interface{}) error {
	var v *tokenValue
	var err error

	if v, err = newTokenValue(value); err != nil {
		return errors.Wrapf(err, "could not set key `%s`", key)
	}

	t.claims[key] = *v

	return nil
}

// Get gets the given key and writes the value into output, if present by
// parsing the JSON using encoding/json.
func (t Token) Get(key string, output interface{}) (err error) {
	var v tokenValue
	var ok bool

	if v, ok = t.claims[key]; !ok {
		return errors.Errorf("value for key `%s` not present in claims", key)
	}

	if err := json.Unmarshal(v.rawValue, &output); err != nil {
		output = nil
		return err
	}

	return nil
}

// GetString returns the value for a given key as a string, or error if this
// is not possible (cannot be a string, or value does not exist)
func (t Token) GetString(key string) (*string, error) {
	var str string

	if err := t.Get(key, &str); err != nil {
		return nil, err
	}

	return &str, nil
}

// SetString sets the given key with value. If, for some reason, the provided
// string cannot be serialised as JSON SetString will panic.
func (t *Token) SetString(key string, value string) {
	// panic if we get an error, we shouldn't fail to set a string value
	if err := t.Set(key, value); err != nil {
		panic(err)
	}
}

// Claims gets the stored claims.
func (t Token) Claims() (map[string]interface{}, error) {
	claims := make(map[string]interface{})

	for key, value := range t.claims {
		var claimValue interface{}

		if err := json.Unmarshal(value.rawValue, &claimValue); err != nil {
			return nil, err
		}

		claims[key] = claimValue
	}

	return claims, nil
}

// ClaimsJSON gets the stored claims as JSON.
func (t Token) ClaimsJSON() ([]byte, error) {
	var claims map[string]interface{}
	var err error

	if claims, err = t.Claims(); err != nil {
		return nil, err
	}

	var data []byte

	if data, err = json.Marshal(claims); err != nil {
		return nil, err
	}

	return data, nil
}

// Footer returns the token's footer
func (t Token) Footer() []byte {
	return t.footer
}

// SetFooter sets the token's footer
func (t *Token) SetFooter(footer []byte) {
	t.footer = footer
}

// V4Sign signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the signature, but which are not present in
// the final token.
// Implicit must be reprovided for successful verification, and can not be
// recovered.
func (t Token) V4Sign(key V4AsymmetricSecretKey, implicit []byte) (*string, error) {

	var encodedClaims []byte
	var err error

	if encodedClaims, err = t.ClaimsJSON(); err != nil {
		return nil, err
	}

	p := packet{encodedClaims, []byte(t.footer)}

	paseto := v4PublicSign(p, key, implicit).Encoded()

	return &paseto, nil
}

// V4Encrypt signs the token, using the given key and implicit bytes. Implicit
// bytes are bytes used to calculate the encrypted token, but which are not
// present in the final token (or its decrypted value).
// Implicit must be reprovided for successful decryption, and can not be
// recovered.
func (t Token) V4Encrypt(key V4SymmetricKey, implicit []byte) (*string, error) {
	var encodedClaims []byte
	var err error

	if encodedClaims, err = t.ClaimsJSON(); err != nil {
		return nil, err
	}

	p := packet{encodedClaims, []byte(t.footer)}

	paseto := v4LocalEncrypt(p, key, implicit, nil).Encoded()

	return &paseto, nil
}

type tokenValue struct {
	// we store the encoded value, and let json.Unmarshal take care of
	// conversion
	rawValue []byte
}

func newTokenValue(value interface{}) (*tokenValue, error) {
	var bytes []byte
	var err error

	if bytes, err = json.Marshal(value); err != nil {
		return nil, err
	}

	return &tokenValue{bytes}, nil
}
