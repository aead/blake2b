// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package blake2b

import (
	"bytes"
	"encoding/hex"
	"hash"
	"testing"
)

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var testVectors = []struct {
	hashsize       int
	key, msg, hash string
}{
	// Test vector https://tools.ietf.org/html/rfc7693#appendix-A
	{
		hashsize: 64,
		msg:      hex.EncodeToString([]byte("abc")),
		hash: "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D1" +
			"7D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923",
	},

	// Test vectors from https://blake2.net/blake2b-test.txt
	{
		hashsize: 64,
		key: "000102030405060708090a0b0c0d0e0f10111213141" +
			"5161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343" +
			"5363738393a3b3c3d3e3f",
		msg: hex.EncodeToString([]byte("")),
		hash: "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786" +
			"b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
	},
	{
		hashsize: 64,
		key: "000102030405060708090a0b0c0d0e0f1011121314151617181" +
			"91a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a" +
			"3b3c3d3e3f",
		msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2" +
			"02122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		hash: "65676d800617972fbd87e4b9514e1c67402b7a331096d3bfac22f1abb95374ab" +
			"c942f16e9ab0ead33b87c91968a6e509e119ff07787b3ef483e1dcdccf6e3022",
	},
	{
		hashsize: 64,
		key: "000102030405060708090a0b0c0d0e0f10111213141516171819" +
			"1a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b" +
			"3c3d3e3f",
		msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4" +
			"04142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60" +
			"6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808" +
			"182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1" +
			"a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c" +
			"2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2" +
			"e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd",
		hash: "d444bfa2362a96df213d070e33fa841f51334e4e76866b8139e8af3bb3398be2" +
			"dfaddcbc56b9146de9f68118dc5829e74b0c28d7711907b121f9161cb92b69a9",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range testVectors {
		h, _ := New512(fromHex(v.key))
		msg := fromHex(v.msg)

		h.Write(msg)
		sum := h.Sum(nil)

		expSum := fromHex(v.hash)
		if !bytes.Equal(sum, expSum) {
			t.Fatalf("Test vector %d : Hash does not match:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(sum), hex.EncodeToString(expSum))
		}
	}
}

func generateSequence(out []byte, seed uint32) {
	a := 0xDEAD4BAD * seed // prime
	b := uint32(1)

	for i := range out { // fill the buf
		t := a + b
		a = b
		b = t
		out[i] = byte(t >> 24)
	}
}

func computeMAC(msg []byte, hashsize int, key []byte) (sum []byte) {
	var h hash.Hash
	switch hashsize {
	default:
		panic("Unexpected hashsize")
	case Size:
		h, _ = New512(key)
	case Size384:
		h, _ = New384(key)
	case Size256:
		h, _ = New256(key)
	case Size160:
		h, _ = New160(key)
	}
	h.Write(msg)
	sum = h.Sum(sum)
	return
}

func computeHash(msg []byte, hashsize int) (sum []byte) {
	switch hashsize {
	case Size:
		hash := Sum512(msg)
		sum = hash[:]
	case Size384:
		hash := Sum384(msg)
		sum = hash[:]
	case Size256:
		hash := Sum256(msg)
		sum = hash[:]
	case Size160:
		hash := Sum160(msg)
		sum = hash[:]
	}
	return
}

// Test function from RFC 7693.
func TestSelfTest(t *testing.T) {
	var result = [32]byte{
		0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD,
		0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA, 0x56,
		0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73,
		0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75,
	}
	var hashLens = [4]int{20, 32, 48, 64}
	var msgLens = [6]int{0, 3, 128, 129, 255, 1024}

	msg := make([]byte, 1024)
	key := make([]byte, 64)

	h, _ := New256(nil)
	for _, hashsize := range hashLens {
		for _, msgLength := range msgLens {
			generateSequence(msg[:msgLength], uint32(msgLength)) // unkeyed hash

			md := computeHash(msg[:msgLength], hashsize)
			h.Write(md)

			generateSequence(key[:], uint32(hashsize)) // keyed hash
			md = computeMAC(msg[:msgLength], hashsize, key[:hashsize])
			h.Write(md)
		}
	}

	sum := h.Sum(nil)
	if !bytes.Equal(sum, result[:]) {
		t.Fatalf("Selftest failed:\nFound: %s\nExpected: %s", hex.EncodeToString(sum), hex.EncodeToString(result[:]))
	}
}

// Benchmarks

func benchmarkSum(b *testing.B, size int) {
	data := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum512(data)
	}
}

func benchmarkWrite(b *testing.B, size int) {
	data := make([]byte, size)
	h, _ := New512(nil)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(data)
	}
}

func BenchmarkWrite128(b *testing.B) { benchmarkWrite(b, 128) }
func BenchmarkWrite1K(b *testing.B)  { benchmarkWrite(b, 1024) }

func BenchmarkSum128(b *testing.B) { benchmarkSum(b, 128) }
func BenchmarkSum1K(b *testing.B)  { benchmarkSum(b, 1024) }
