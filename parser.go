package paseto

import (
	"time"
)

type Parser struct {
	rules []Rule
}

func NewParser() Parser {
	return Parser{nil}
}

func NewParserValidNow() Parser {
	return Parser{[]Rule{ValidAt(time.Now())}}
}

func MakeParser(rules []Rule) Parser {
	return Parser{rules}
}

func (p Parser) ParseV4Local(key V4SymmetricKey, tainted string, implicit []byte) (*Token, error) {
	var message Message
	var err error

	if message, err = NewMessage(V4Local, tainted); err != nil {
		return nil, err
	}

	var token *Token
	if token, err = message.V4Decrypt(key, implicit); err != nil {
		return nil, err
	}

	return p.validate(*token)
}

func (p Parser) ParseV4Public(key V4AsymmetricPublicKey, tainted string, implicit []byte) (*Token, error) {
	var message Message
	var err error

	if message, err = NewMessage(V4Public, tainted); err != nil {
		return nil, err
	}

	var token *Token
	if token, err = message.V4Verify(key, implicit); err != nil {
		return nil, err
	}

	return p.validate(*token)
}

func (p Parser) validate(token Token) (*Token, error) {
	for _, rule := range p.rules {
		if err := rule(token); err != nil {
			return nil, err
		}
	}

	return &token, nil
}

func (p *Parser) SetRules(rules []Rule) {
	p.rules = rules
}

func (p *Parser) AddRule(rule ...Rule) {
	p.rules = append(p.rules, rule...)
}
