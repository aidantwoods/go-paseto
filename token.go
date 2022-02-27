package paseto

import (
	"encoding/json"

	"github.com/pkg/errors"
)

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

type Token struct {
	claims map[string]tokenValue
	footer []byte
}

func NewToken() Token {
	return Token{make(map[string]tokenValue), nil}
}

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

func NewTokenFromClaimsJson(claimsData []byte, footer []byte) (*Token, error) {
	var claims map[string]interface{}
	var err error

	if err = json.Unmarshal(claimsData, &claims); err != nil {
		return nil, err
	}

	return MakeToken(claims, footer)
}

func (t *Token) Set(key string, value interface{}) error {
	var v *tokenValue
	var err error

	if v, err = newTokenValue(value); err != nil {
		return err
	}

	t.claims[key] = *v

	return nil
}

func (t Token) Get(key string, output interface{}) (err error, exists bool) {
	var v tokenValue
	var ok bool

	if v, ok = t.claims[key]; !ok {
		return errors.Errorf("Value for key not present in claims"), false
	}

	if err := json.Unmarshal(v.rawValue, &output); err != nil {
		output = nil
		return err, true
	}

	return nil, true
}

func (t Token) GetString(key string) (*string, error) {
	var str string

	if err, _ := t.Get(key, &str); err != nil {
		return nil, err
	}

	return &str, nil
}

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

func (t Token) ClaimsJson() ([]byte, error) {
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

func (t Token) V4Sign(key V4AsymmetricSecretKey, implicit []byte) (*Message, error) {

	var encodedClaims []byte
	var err error

	if encodedClaims, err = t.ClaimsJson(); err != nil {
		return nil, err
	}

	packet := Packet{encodedClaims, []byte(t.footer)}

	message := V4PublicSign(packet, key, implicit)

	return &message, nil
}

func (t Token) V4Encrypt(key V4SymmetricKey, implicit []byte) (*Message, error) {
	var encodedClaims []byte
	var err error

	if encodedClaims, err = t.ClaimsJson(); err != nil {
		return nil, err
	}

	packet := Packet{encodedClaims, []byte(t.footer)}

	message := V4LocalEncrypt(packet, key, implicit)

	return &message, nil
}
