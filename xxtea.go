package tea

import (
	"encoding/binary"
	"fmt"
)

type XXTinyEncryptionAlgorithm struct {
	keys []uint32
	size uint32
}

// NewXXTEA return a XXTinyEncryptionAlgorithm struct
func NewXXTEA(key []byte, size uint32) (*XXTinyEncryptionAlgorithm, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("invalid key size %d", len(key))
	}
	return &XXTinyEncryptionAlgorithm{size: size, keys: []uint32{
		binary.BigEndian.Uint32(key[0:]),
		binary.BigEndian.Uint32(key[4:]),
		binary.BigEndian.Uint32(key[8:]),
		binary.BigEndian.Uint32(key[12:]),
	}}, nil
}

// BlockSize returns the cipher's block size.
func (c *XXTinyEncryptionAlgorithm) BlockSize() int { return int(c.size) }

// Encrypt encrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (c *XXTinyEncryptionAlgorithm) Encrypt(dst, src []byte) {
	n := c.size / 4
	words := make([]uint32, n)
	q := 6 + 52/n

	for i := uint32(0); i < n; i++ {
		words[i] = binary.BigEndian.Uint32(src[i*4:])
	}

	v0, v1 := words[0], words[n-1]

	var sum uint32
	for i := uint32(0); i < q; i++ {
		sum += delta
		e := (sum >> 2) & 3

		p := uint32(0)
		for p = 0; p < n-1; p++ {
			v0 = words[p+1]
			words[p] += c.mx(v0, v1, sum, p, e)
			v1 = words[p]
		}
		v0 = words[0]
		words[n-1] += c.mx(v0, v1, sum, p, e)
		v1 = words[n-1]
	}

	for i := uint32(0); i < n; i++ {
		binary.BigEndian.PutUint32(dst[4*i:], words[i])
	}
}

// Decrypt decrypts the first block in src into dst.
// Dst and src must overlap entirely or not at all.
func (c *XXTinyEncryptionAlgorithm) Decrypt(dst, src []byte) {
	var (
		n     = c.size / 4
		words = make([]uint32, n)
		q     = 6 + 52/n
		sum   = q * delta
	)

	for i := uint32(0); i < n; i++ {
		words[i] = binary.BigEndian.Uint32(src[i*4:])
	}
	v0, v1 := words[0], words[n-1]

	for i := uint32(0); i < q; i++ {
		e := (sum >> 2) & 3
		var p uint32
		for p = n - 1; p > 0; p-- {
			v1 = words[p-1]
			words[p] -= c.mx(v0, v1, sum, p, e)
			v0 = words[p]
		}
		v1 = words[n-1]
		words[0] -= c.mx(v0, v1, sum, p, e)
		v0 = words[0]
		sum -= delta
	}

	for i := uint32(0); i < n; i++ {
		binary.BigEndian.PutUint32(dst[4*i:], words[i])
	}
}

func (c *XXTinyEncryptionAlgorithm) mx(v0, v1, sum, p, e uint32) uint32 {
	return (((v1 >> 5) ^ (v0 << 2)) + ((v0 >> 3) ^ (v1 << 4))) ^ ((sum ^ v0) + (c.keys[(p&3)^e] ^ v1))
}
