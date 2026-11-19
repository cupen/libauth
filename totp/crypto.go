package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var errTruncatedCiphertext = errors.New("ciphertext is truncated")

// secretCipher seals TOTP secrets with AES-256-GCM. The user ID is the
// additional authenticated data, binding a ciphertext to the credential it
// was issued for: copying a row to another user makes it undecryptable.
//
// Ciphertext layout (opaque to Store implementations): nonce || sealed.
// Changing the AAD or layout is a storage-format change and requires a
// migration.
type secretCipher struct {
	aead cipher.AEAD
	rand io.Reader
}

func newSecretCipher(key []byte, r io.Reader) (*secretCipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: encryption key must be exactly %d bytes, got %d", ErrInvalidConfig, KeySize, len(key))
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, fmt.Errorf("%w: initialise AES: %v", ErrInvalidConfig, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialise AES-GCM: %v", ErrInvalidConfig, err)
	}
	if r == nil {
		r = rand.Reader
	}
	return &secretCipher{aead: aead, rand: r}, nil
}

func (c *secretCipher) seal(userID string, secret []byte) ([]byte, error) {
	n := c.aead.NonceSize()
	nonce := make([]byte, n)
	if _, err := io.ReadFull(c.rand, nonce); err != nil {
		return nil, fmt.Errorf("libauth: generate TOTP nonce: %w", err)
	}
	out := make([]byte, 0, n+len(secret)+c.aead.Overhead())
	out = append(out, nonce...)
	return c.aead.Seal(out, nonce, secret, []byte(userID)), nil
}

func (c *secretCipher) open(userID string, sealed []byte) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(sealed) < n+c.aead.Overhead() {
		return nil, fmt.Errorf("libauth: decrypt TOTP secret: %w", errTruncatedCiphertext)
	}
	nonce, body := sealed[:n], sealed[n:]
	secret, err := c.aead.Open(nil, nonce, body, []byte(userID))
	if err != nil {
		return nil, fmt.Errorf("libauth: decrypt TOTP secret: %w", err)
	}
	return secret, nil
}
