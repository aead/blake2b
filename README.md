[![Godoc Reference](https://godoc.org/github.com/aead/blake2b?status.svg)](https://godoc.org/github.com/aead/blake2b)

## The BLAKE2b hash algorithm

BLAKE2b is a fast cryptographic hash function described in [RFC 7963](https://tools.ietf.org/html/rfc7693).
BLAKE2b can be directly keyed, making it functionally equivalent to a Message Authentication Code (MAC).

### Recommendation 
This BLAKE2b implementation was submited to the golang x/crypto repo.
I recommend to use the offical [x/crypto/blake2b](https://godoc.org/golang.org/x/crypto/blake2b) package if possible.

### Installation

Install in your GOPATH: `go get -u github.com/aead/blake2b`

### Performance

**AMD64**  
Hardware: Intel i7-6500U 2.50GHz x 2  
System: Linux Ubuntu 16.04 - kernel: 4.4.0-64-generic  
Go version: 1.8.0  
```
AVX2
name        speed           cpb
Write128-4  756MB/s ± 1%    3.15
Write1K-4   842MB/s ± 0%    2.83
Sum128-4    658MB/s ± 0%    3.62
Sum1K-4     825MB/s ± 0%    2.89

SSE4.1
name        speed           cpb
Write128-4  654MB/s ± 1%    3.65
Write1K-4   739MB/s ± 0%    3.23
Sum128-4    578MB/s ± 0%    4.12
Sum1K-4     728MB/s ± 0%    3.27
```
