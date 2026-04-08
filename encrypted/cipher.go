package encrypted

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/nacl/box"

	"github.com/Arceliar/ironwood/network"
)

// sessionCipher abstracts the per-packet seal/open operations so we can
// swap between NaCl (XSalsa20-Poly1305) and AES-256-GCM.
type sessionCipher interface {
	Seal(out, plaintext []byte, nonce uint64) []byte
	Open(out, ciphertext []byte, nonce uint64) ([]byte, bool)
	Overhead() int
}

// newSessionCipher creates the appropriate cipher from a precomputed shared key.
func newSessionCipher(mode network.CipherMode, shared *boxShared) sessionCipher {
	switch mode {
	case network.CipherAESGCM:
		return newAESGCMCipher(shared)
	default:
		return &naclCipher{shared: shared}
	}
}

// naclCipher wraps the existing XSalsa20-Poly1305 box operations.
type naclCipher struct {
	shared *boxShared
}

func (c *naclCipher) Seal(out, plaintext []byte, nonce uint64) []byte {
	n := nonceForUint64(nonce)
	return box.SealAfterPrecomputation(out, plaintext, (*[24]byte)(&n), (*[32]byte)(c.shared))
}

func (c *naclCipher) Open(out, ciphertext []byte, nonce uint64) ([]byte, bool) {
	n := nonceForUint64(nonce)
	return box.OpenAfterPrecomputation(out, ciphertext, (*[24]byte)(&n), (*[32]byte)(c.shared))
}

func (c *naclCipher) Overhead() int {
	return box.Overhead
}

// aesgcmCipher uses AES-256-GCM which is hardware accelerated on modern CPUs.
type aesgcmCipher struct {
	aead cipher.AEAD
}

func newAESGCMCipher(shared *boxShared) *aesgcmCipher {
	// Derive a 32-byte AES key from the NaCl shared secret via SHA-256.
	// The shared secret is already a Curve25519 ECDH output, so this is safe.
	key := sha256.Sum256(shared[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic("aes.NewCipher: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("cipher.NewGCM: " + err.Error())
	}
	return &aesgcmCipher{aead: aead}
}

func (c *aesgcmCipher) Seal(out, plaintext []byte, nonce uint64) []byte {
	n := aesgcmNonce(nonce)
	return c.aead.Seal(out, n[:], plaintext, nil)
}

func (c *aesgcmCipher) Open(out, ciphertext []byte, nonce uint64) ([]byte, bool) {
	n := aesgcmNonce(nonce)
	result, err := c.aead.Open(out, n[:], ciphertext, nil)
	return result, err == nil
}

func (c *aesgcmCipher) Overhead() int {
	return c.aead.Overhead()
}

// aesgcmNonce builds a 12-byte nonce from a uint64 counter.
func aesgcmNonce(u64 uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], u64)
	return nonce
}
