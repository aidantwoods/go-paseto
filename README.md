# Go Paseto [![Go-Paseto](https://github.com/aidantwoods/go-paseto/actions/workflows/ci.yml/badge.svg)](https://github.com/aidantwoods/go-paseto/actions/workflows/ci.yml)

A Go implementation of [PASETO](https://github.com/paragonie/paseto).

## ⚠️  WARNING: IMPLEMENTATION IS A PRE-RELEASE.

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).


# Contents
* [What is Paseto?](#what-is-paseto)
  * [Key Differences between Paseto and JWT](#key-differences-between-paseto-and-jwt)
* [Installation](#installation)
  * [Requirements](#requirements)
  * [Dependencies](#dependencies)
* [Overview of the Swift library](#overview-of-the-swift-library)
* [Supported Paseto Versions](#supported-paseto-versions)

# What is Paseto?

[Paseto](https://github.com/paragonie/paseto) (Platform-Agnostic SEcurity
TOkens) is a specification for secure stateless tokens.

## Key Differences between Paseto and JWT

Unlike JSON Web Tokens (JWT), which gives developers more than enough rope with
which to hang themselves, Paseto only allows secure operations. JWT gives you
"algorithm agility", Paseto gives you "versioned protocols". It's incredibly
unlikely that you'll be able to use Paseto in
[an insecure way](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries).

> **Caution:** Neither JWT nor Paseto were designed for
> [stateless session management](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/).
> Paseto is suitable for tamper-proof cookies, but cannot prevent replay attacks
> by itself.

# Installation

```bash
go get -u github.com/aidantwoods/go-paseto
```

# Overview of the Go library

Okay, let's create a token:
```go
token := NewToken()

token.SetIssuedAt(time.Now())
token.SetNotBefore(time.Now().Add(2 * time.Minute))
token.SetExpiration(time.Now().Add(2 * time.Hour))

token.SetString("user-id", "<uuid>")
```

Now encrypt it:
```go
key := NewV4SymmetricKey() // don't share this!!

encrypted, err := token.V4Encrypt(key, nil)
if err != nil {
    // panic or deal with error
}
```

Or sign it (this allows recievers to verify it without sharing secrets):
```go

secretKey := NewV4AsymmetricSecretKey() // don't share this!!!
publicKey := secretKey.Public() // DO share this one

signed, err := token.V4Sign(secretKey, nil)
if err != nil {
    // panic or deal with error
}
```

To handle a recieved token, let's use an example from Paseto's test vectors:

The Paseto token is as follows
```
v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
```

And the public key, given in hex is:
```
1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2
```

Importing a public key, and then verifying a token:

```go
publicKey, err := NewV4AsymmetricPublicKeyFromHex("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2") // this wil fail if given key in an invalid format
signed := "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"

parser := NewParser()
parser.
token, err := parser.ParseV4Public(publicKey, signed, nil) // this will fail if either rules fail, or

claimsJSON, _ := token.ClaimsJSON()

// the following will succeed
require.JSONEq(t,
    "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    string(claimsJson),
)
require.Equal(t,
    "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
    string(token.Footer()),
)
```

# Supported Paseto Versions
## Version 2
Version 2 is fully supported.
## Version 3
Version 3 supports only local mode (so far).
## Version 4
Version 4 is fully supported.
