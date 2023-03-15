# Go Paseto [![Go-Paseto](https://github.com/aidantwoods/go-paseto/actions/workflows/ci.yml/badge.svg)](https://github.com/aidantwoods/go-paseto/actions/workflows/ci.yml)

A Go implementation of [PASETO](https://github.com/paragonie/paseto).

Paseto is everything you love about JOSE (JWT, JWE, JWS) without any of the
[many design deficits that plague the JOSE standards](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid).


# Contents
* [What is Paseto?](#what-is-paseto)
  * [Key Differences between Paseto and JWT](#key-differences-between-paseto-and-jwt)
* [Installation](#installation)
* [Overview of the Go library](#overview-of-the-go-library)
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
go get -u aidanwoods.dev/go-paseto
```

# Overview of the Go library

Okay, let's create a token:
```go
token := paseto.NewToken()

token.SetIssuedAt(time.Now())
token.SetNotBefore(time.Now())
token.SetExpiration(time.Now().Add(2 * time.Hour))

token.SetString("user-id", "<uuid>")
```

Now encrypt it:
```go
key := paseto.NewV4SymmetricKey() // don't share this!!

encrypted := token.V4Encrypt(key, nil)
```

Or sign it (this allows recievers to verify it without sharing secrets):
```go

secretKey := paseto.NewV4AsymmetricSecretKey() // don't share this!!!
publicKey := secretKey.Public() // DO share this one

signed := token.V4Sign(secretKey, nil)
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
publicKey, err := paseto.NewV4AsymmetricPublicKeyFromHex("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2") // this wil fail if given key in an invalid format
signed := "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9"

parser := paseto.NewParserWithoutExpiryCheck() // only used because this example token has expired, use NewParser() (which checks expiry by default)
token, err := parser.ParseV4Public(publicKey, signed, nil) // this will fail if parsing failes, cryptographic checks fail, or validation rules fail

// the following will succeed
require.JSONEq(t,
    "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
    string(token.ClaimsJSON()),
)
require.Equal(t,
    "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
    string(token.Footer()),
)
require.NoError(t, err)
```

# Supported Claims Validators
The following validators are supported:

```go
func ForAudience(audience string) Rule
func IdentifiedBy(identifier string) Rule
func IssuedBy(issuer string) Rule
func NotExpired() Rule
func Subject(subject string) Rule
func ValidAt(t time.Time) Rule
```

A token using claims all the claims which can be validated can be constructed as follows:

```go
token := paseto.NewToken()

token.SetAudience("audience")
token.SetJti("identifier")
token.SetIssuer("issuer")
token.SetSubject("subject")

token.SetExpiration(time.Now().Add(time.Minute))
token.SetNotBefore(time.Now())
token.SetIssuedAt(time.Now())

secretKeyHex := "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
secretKey, _ := paseto.NewV4AsymmetricSecretKeyFromHex(secretKeyHex)

signed := token.V4Sign(secretKey, nil)
```

The token in `signed` can then be validated using a public key as follows:
```go
parser := paseto.NewParser()
parser.AddRule(paseto.ForAudience("audience"))
parser.AddRule(paseto.IdentifiedBy("identifier"))
parser.AddRule(paseto.IssuedBy("issuer"))
parser.AddRule(paseto.Subject("subject"))
parser.AddRule(paseto.NotExpired())
parser.AddRule(paseto.ValidAt(time.Now()))

publicKeyHex := "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"
publicKey, err := paseto.NewV4AsymmetricPublicKeyFromHex(publicKeyHex)
if err != nil {
    // panic or deal with error of invalid key
}

parsedToken, err := parser.ParseV4Public(publicKey, signed, nil)
if err != nil {
    // deal with error of token which failed to be validated, or cryptographically verified
}
```

If everything succeeds, the value in `parsedToken` will be equivalent to that in `token`.

# Supported Paseto Versions
## Version 4
Version 4 is fully supported.
## Version 3
Version 3 is fully supported.
## Version 2
Version 2 is fully supported.

# Supported Go Versions
Only [officially supported](https://go.dev/doc/devel/release#policy) versions of Go will be
supported by Go Paseto. Versions of Go which have recently gone out of support may continue to work
with this library for some time, however this is not guarenteed and should not be relied on.

When support for an out of date version of Go is dropped, this will be done as part of a minor
version bump.