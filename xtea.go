package tea

import (
	"encoding/binary"
	"fmt"
)

type XTinyEncryptionAlgorithm struct {
	keys []uint32
}

// NewXTEA return a XTinyEncryptionAlgorithm struct
func NewXTEA(key []byte) (*XTinyEncryptionAlgorithm, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("invalid key size %d", len(key))
	}
	return &XTinyEncryptionAlgorithm{keys: []uint32{
		binary.BigEndian.Uint32(key[0:]),
		binary.BigEndian.Uint32(key[4:]),
		binary.BigEndian.Uint32(key[8:]),
		binary.BigEndian.Uint32(key[12:]),
	}}, nil
}

// BlockSize returns the cipher's block size.
func (t *XTinyEncryptionAlgorithm) BlockSize() int { return 8 }

// Encrypt encrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (t *XTinyEncryptionAlgorithm) Encrypt(dst, src []byte) {
	v0, v1 := binary.BigEndian.Uint32(src), binary.BigEndian.Uint32(src[4:])

	var sum uint32
	for i := 0; i < 32; i++ {
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + t.keys[sum&3])
		sum += delta
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + t.keys[(sum>>11)&3])
	}

	binary.BigEndian.PutUint32(dst, v0)
	binary.BigEndian.PutUint32(dst[4:], v1)
}

// Decrypt decrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (t *XTinyEncryptionAlgorithm) Decrypt(dst, src []byte) {
	v0, v1 := binary.BigEndian.Uint32(src[0:4]), binary.BigEndian.Uint32(src[4:8])

	sum := delta << 5
	for i := 0; i < 32; i++ {
		v1 -= ((v0<<4 ^ v0>>5) + v0) ^ (sum + t.keys[(sum>>11)&3])
		sum -= delta
		v0 -= ((v1<<4 ^ v1>>5) + v1) ^ (sum + t.keys[sum&3])
	}

	binary.BigEndian.PutUint32(dst, v0)
	binary.BigEndian.PutUint32(dst[4:], v1)
}
