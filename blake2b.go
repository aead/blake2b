// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Package blake2b implemnets the BLAKE2b hash algorithm as
// defined in RFC 7693.
package blake2b

import (
	"encoding/binary"
	"errors"
	"hash"
)

const (
	// BlockSize is the blocksize of BLAKE2b in bytes.
	BlockSize = 128
	// Size is the hash size of BLAKE2b-512 in bytes.
	Size = 64
	// Size384 is the hash size of BLAKE2b-384 in bytes.
	Size384 = 48
	// Size256 is the hash size of BLAKE2b-256 in bytes.
	Size256 = 32
	// Size160 is the hash size of BLAKE2b-160 in bytes.
	Size160 = 20
)

var errKeySize = errors.New("invalid key size")

var iv = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// Sum512 returns the BLAKE2b-512 checksum of the data.
func Sum512(data []byte) [Size]byte {
	var sum [Size]byte
	checkSum(&sum, Size, data)
	return sum
}

// Sum384 returns the BLAKE2b-384 checksum of the data.
func Sum384(data []byte) [Size384]byte {
	var sum [Size]byte
	var sum384 [Size384]byte
	checkSum(&sum, Size384, data)
	copy(sum384[:], sum[:Size384])
	return sum384
}

// Sum256 returns the BLAKE2b-256 checksum of the data.
func Sum256(data []byte) [Size256]byte {
	var sum [Size]byte
	var sum256 [Size256]byte
	checkSum(&sum, Size256, data)
	copy(sum256[:], sum[:Size256])
	return sum256
}

// Sum160 returns the BLAKE2b-160 checksum of the data.
func Sum160(data []byte) [Size160]byte {
	var sum [Size]byte
	var sum160 [Size160]byte
	checkSum(&sum, Size160, data)
	copy(sum160[:], sum[:Size160])
	return sum160
}

// New512 returns a new hash.Hash computing the BLAKE2b-512 checksum.
// A non-nil key turns the hash into a MAC. The key must between 0 and 64 byte.
func New512(key []byte) (hash.Hash, error) { return newDigest(Size, key) }

// New384 returns a new hash.Hash computing the BLAKE2b-384 checksum.
// A non-nil key turns the hash into a MAC. The key must between 0 and 64 byte.
func New384(key []byte) (hash.Hash, error) { return newDigest(Size384, key) }

// New256 returns a new hash.Hash computing the BLAKE2b-256 checksum.
// A non-nil key turns the hash into a MAC. The key must between 0 and 64 byte.
func New256(key []byte) (hash.Hash, error) { return newDigest(Size256, key) }

// New160 returns a new hash.Hash computing the BLAKE2b-160 checksum.
// A non-nil key turns the hash into a MAC. The key must between 0 and 64 byte.
func New160(key []byte) (hash.Hash, error) { return newDigest(Size160, key) }

func newDigest(hashsize int, key []byte) (*digest, error) {
	if len(key) > Size {
		return nil, errKeySize
	}
	d := &digest{
		size:   hashsize,
		keyLen: len(key),
	}
	copy(d.key[:], key)
	d.Reset()
	return d, nil
}

func checkSum(sum *[Size]byte, hashsize int, data []byte) {
	var (
		h     [8]uint64
		c     [2]uint64
		block [BlockSize]byte
		off   int
	)

	h = iv
	h[0] ^= uint64(hashsize) | (1 << 16) | (1 << 24)

	if length := len(data); length > BlockSize {
		n := length & (^(BlockSize - 1))
		if length == n {
			n -= BlockSize
		}
		hashBlocks(&h, &c, 0, data[:n])
		data = data[n:]
	}
	off += copy(block[:], data)

	dif := uint64(BlockSize - off)
	if c[0] < dif {
		c[1]--
	}
	c[0] -= dif

	hashBlocks(&h, &c, 0xFFFFFFFFFFFFFFFF, block[:])

	for i, v := range h[:(hashsize+7)/8] {
		binary.LittleEndian.PutUint64(sum[8*i:], v)
	}
}

type digest struct {
	h     [8]uint64
	c     [2]uint64
	size  int
	block [BlockSize]byte
	off   int

	key    [BlockSize]byte
	keyLen int
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Size() int { return d.size }

func (d *digest) Reset() {
	d.h = iv
	d.h[0] ^= uint64(d.size) | (uint64(d.keyLen) << 8) | (1 << 16) | (1 << 24)
	d.off, d.c[0], d.c[1] = 0, 0, 0
	if d.keyLen > 0 {
		d.block = d.key
		d.off = BlockSize
	}
}

func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)

	if d.off > 0 {
		dif := BlockSize - d.off
		if n > dif {
			copy(d.block[d.off:], p[:dif])
			hashBlocks(&d.h, &d.c, 0, d.block[:])
			d.off = 0
			p = p[dif:]
		} else {
			d.off += copy(d.block[d.off:], p)
			return
		}
	}

	if length := len(p); length > BlockSize {
		nn := length & (^(BlockSize - 1))
		if length == nn {
			nn -= BlockSize
		}
		hashBlocks(&d.h, &d.c, 0, p[:nn])
		p = p[nn:]
	}

	if len(p) > 0 {
		d.off += copy(d.block[:], p)
	}

	return
}

func (d *digest) Sum(b []byte) []byte {
	var block [BlockSize]byte
	h := d.h
	c := d.c

	copy(block[:], d.block[:d.off])
	dif := uint64(BlockSize - d.off)
	if c[0] < dif {
		c[1]--
	}
	c[0] -= dif

	hashBlocks(&h, &c, 0xFFFFFFFFFFFFFFFF, block[:])

	var sum [Size]byte
	for i, v := range h[:(d.size+7)/8] {
		binary.LittleEndian.PutUint64(sum[8*i:], v)
	}

	return append(b, sum[:d.size]...)
}
