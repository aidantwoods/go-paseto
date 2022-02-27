package paseto

import (
	"crypto/subtle"
	"errors"
	"time"
)

type Rule func(token Token) error

func ForAudience(audience string) Rule {
	return func(token Token) error {
		var tAud *string
		var err error

		if tAud, err = token.GetAudience(); err != nil {
			return err
		}

		tAudBytes := []byte(*tAud)
		audBytes := []byte(audience)

		if subtle.ConstantTimeCompare(tAudBytes, audBytes) == 1 {
			return nil
		}

		return errors.New("this token is not intended for `" + audience + "`. `" + *tAud + "` found")
	}
}

func IdentifiedBy(identifier string) Rule {
	return func(token Token) error {
		var tJti *string
		var err error

		if tJti, err = token.GetJti(); err != nil {
			return err
		}

		tJtiBytes := []byte(*tJti)
		jtiBytes := []byte(identifier)

		if subtle.ConstantTimeCompare(tJtiBytes, jtiBytes) == 0 {
			return errors.New("this token is not identified by `" + identifier + "`. `" + *tJti + "` found")
		}

		return nil
	}
}

func IssuedBy(issuer string) Rule {
	return func(token Token) error {
		var tIss *string
		var err error

		if tIss, err = token.GetIssuer(); err != nil {
			return err
		}

		tIssBytes := []byte(*tIss)
		issBytes := []byte(issuer)

		if subtle.ConstantTimeCompare(tIssBytes, issBytes) == 0 {
			return errors.New("this token is not issued by `" + issuer + "`. `" + *tIss + "` found")
		}

		return nil
	}
}

func NotExpired() Rule {
	return func(token Token) error {
		var exp *time.Time
		var err error

		if exp, err = token.GetExpiration(); err != nil {
			return err
		}

		now := time.Now()

		if now.After(*exp) {
			return errors.New("this token has expired")
		}

		return nil
	}
}

func Subject(subject string) Rule {
	return func(token Token) error {
		var tSub *string
		var err error

		if tSub, err = token.GetSubject(); err != nil {
			return err
		}

		tSubBytes := []byte(*tSub)
		subBytes := []byte(subject)

		if subtle.ConstantTimeCompare(tSubBytes, subBytes) == 1 {
			return nil
		}

		return errors.New("this token is not related to `" + subject + "`. `" + *tSub + "` found")
	}
}

func ValidAt(t time.Time) Rule {
	return func(token Token) error {
		var err error

		var iat *time.Time
		if iat, err = token.GetIssuedAt(); err != nil {
			return err
		}
		if t.Before(*iat) {
			return errors.New("the ValidAt time is before this token was issued")
		}

		var nbf *time.Time
		if nbf, err = token.GetNotBefore(); err != nil {
			return err
		}
		if t.Before(*nbf) {
			return errors.New("the ValidAt time is before this token's not before time")
		}

		var exp *time.Time
		if exp, err = token.GetExpiration(); err != nil {
			return err
		}
		if t.After(*exp) {
			return errors.New("the ValidAt time is after this token expires")
		}

		return nil
	}
}

func (t Token) GetAudience() (*string, error) {
	return t.GetString("aud")
}

func (t Token) GetExpiration() (*time.Time, error) {
	var expStr string

	if err, _ := t.Get("exp", &expStr); err != nil {
		return nil, err
	}

	exp, err := time.Parse(time.RFC3339, expStr)

	return &exp, err
}

func (t Token) GetIssuedAt() (*time.Time, error) {
	var iatStr string

	if err, _ := t.Get("iat", &iatStr); err != nil {
		return nil, err
	}

	iat, err := time.Parse(time.RFC3339, iatStr)

	return &iat, err
}

func (t Token) GetIssuer() (*string, error) {
	return t.GetString("iss")
}

func (t Token) GetJti() (*string, error) {
	return t.GetString("jti")
}

func (t Token) GetNotBefore() (*time.Time, error) {
	var nbfStr *string

	if err, _ := t.Get("nbf", &nbfStr); err != nil {
		return nil, err
	}

	nbf, err := time.Parse(time.RFC3339, *nbfStr)

	return &nbf, err
}

func (t Token) GetSubject() (*string, error) {
	return t.GetString("sub")
}

func (t *Token) SetAudience(audience string) {
	t.SetString("aud", audience)
}

func (t *Token) SetExpiration(exp time.Time) {
	t.SetString("exp", exp.Format(time.RFC3339))
}

func (t *Token) SetIssuedAt(iat time.Time) {
	t.SetString("iat", iat.Format(time.RFC3339))
}

func (t *Token) SetIssuer(issuer string) {
	t.SetString("iss", issuer)
}

func (t *Token) SetJti(identifier string) {
	t.SetString("jti", identifier)
}

func (t *Token) SetNotBefore(nbf time.Time) {
	t.SetString("nbf", nbf.Format(time.RFC3339))
}

func (t *Token) SetSubject(subject string) {
	t.SetString("sub", subject)
}
