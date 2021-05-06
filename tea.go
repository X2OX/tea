package tea

import (
	"encoding/binary"
	"fmt"
)

var delta = uint32(0x9E3779B9)

type TinyEncryptionAlgorithm struct {
	k0, k1, k2, k3 uint32
}

// NewTEA return a TinyEncryptionAlgorithm struct
func NewTEA(key []byte) (*TinyEncryptionAlgorithm, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("invalid key size %d", len(key))
	}
	return &TinyEncryptionAlgorithm{
		k0: binary.BigEndian.Uint32(key[0:]),
		k1: binary.BigEndian.Uint32(key[4:]),
		k2: binary.BigEndian.Uint32(key[8:]),
		k3: binary.BigEndian.Uint32(key[12:]),
	}, nil
}

// BlockSize returns the cipher's block size.
func (t *TinyEncryptionAlgorithm) BlockSize() int { return 8 }

// Encrypt encrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (t *TinyEncryptionAlgorithm) Encrypt(dst, src []byte) {
	v0, v1 := binary.BigEndian.Uint32(src), binary.BigEndian.Uint32(src[4:])

	var sum uint32
	for i := 0; i < 32; i++ {
		sum += delta
		v0 += ((v1 << 4) + t.k0) ^ (v1 + sum) ^ ((v1 >> 5) + t.k1)
		v1 += ((v0 << 4) + t.k2) ^ (v0 + sum) ^ ((v0 >> 5) + t.k3)
	}

	binary.BigEndian.PutUint32(dst, v0)
	binary.BigEndian.PutUint32(dst[4:], v1)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (t *TinyEncryptionAlgorithm) Decrypt(dst, src []byte) {
	v0, v1 := binary.BigEndian.Uint32(src[0:4]), binary.BigEndian.Uint32(src[4:8])

	sum := delta << 5
	for i := 0; i < 32; i++ {
		v1 -= ((v0 << 4) + t.k2) ^ (v0 + sum) ^ ((v0 >> 5) + t.k3)
		v0 -= ((v1 << 4) + t.k0) ^ (v1 + sum) ^ ((v1 >> 5) + t.k1)
		sum -= delta
	}

	binary.BigEndian.PutUint32(dst, v0)
	binary.BigEndian.PutUint32(dst[4:], v1)
}
