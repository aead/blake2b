[![Godoc Reference](https://godoc.org/github.com/aead/blake2b?status.svg)](https://godoc.org/github.com/aead/blake2b)

## Deprecated

This BLAKE2b implementation was submited to the golang x/crypto repo.
I recommend to use the offical [x/crypto/blake2b](https://godoc.org/golang.org/x/crypto/blake2b) package.

## The BLAKE2b hash algorithm

BLAKE2b is a fast cryptographic hash function described in [RFC 7963](https://tools.ietf.org/html/rfc7693).
BLAKE2b can be directly keyed, making it functionally equivalent to a Message Authentication Code (MAC).

### Installation

Install in your GOPATH: `go get -u github.com/aead/blake2b`
