// Package branca implements the branca token specification
// (https://github.com/tuupola/branca-spec): authenticated, encrypted tokens
// built on XChaCha20-Poly1305 and base62 encoded.
//
//	Version (0xBA) || Timestamp (4B) || Nonce (24B) || Ciphertext || Tag (16B)
//
// The header is the AEAD's additional data, so its timestamp cannot be
// tampered with. TTL is applied by the consumer after decryption: the same
// token may carry different validity windows for different consumers.
package branca

import (
	"crypto/rand"
	"encoding"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize is the exact branca key length: 32 bytes.
	KeySize = chacha20poly1305.KeySize

	versionByte = 0xBA
	nonceSize   = 24
	headerSize  = 1 + 4 + nonceSize // version || timestamp || nonce
	tagSize     = 16
	minTokenLen = headerSize + tagSize
)

// Clock returns the current time. Inject one via WithNow.
type Clock func() time.Time

// Token is the decoded form of a branca token.
type Token struct {
	Token     string
	Timestamp time.Time
	Payload   []byte
}

// Bytes is a raw-byte payload for callers without a typed marshaler.
type Bytes []byte

func (b Bytes) MarshalBinary() ([]byte, error) { return b, nil }
func (b *Bytes) UnmarshalBinary(raw []byte) error {
	*b = append((*b)[:0], raw...)
	return nil
}

// Branca encodes and decodes branca tokens with one 32-byte key. Safe for
// concurrent use.
type Branca struct {
	key  []byte
	now  Clock
	rand io.Reader
}

// Option customises a Branca.
type Option func(*Branca)

// WithNow overrides the clock used for encoding and age checks.
func WithNow(now Clock) Option {
	return func(b *Branca) {
		if now != nil {
			b.now = now
		}
	}
}

// WithRand overrides the randomness source nonces are drawn from.
func WithRand(r io.Reader) Option {
	return func(b *Branca) {
		if r != nil {
			b.rand = r
		}
	}
}

// New returns a Branca keyed with a 32-byte secret.
func New(key []byte, opts ...Option) (*Branca, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: branca key must be exactly %d bytes, got %d", ErrInvalidKey, KeySize, len(key))
	}
	b := &Branca{
		key:  append([]byte(nil), key...),
		now:  time.Now,
		rand: rand.Reader,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(b)
		}
	}
	return b, nil
}

// Encode encrypts v and returns the token, stamping the current time into
// the authenticated header.
func (b *Branca) Encode(v encoding.BinaryMarshaler) (string, error) {
	raw, err := v.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("libauth: marshal payload: %w", err)
	}
	return b.encodeBytes(raw)
}

// Decode verifies, decrypts and unmarshals the payload. A positive ttl
// rejects tokens older than ttl; the check runs after decryption, as the
// spec requires.
func (b *Branca) Decode(token string, ttl time.Duration, into encoding.BinaryUnmarshaler) (*Token, error) {
	tok, err := b.open(token, ttl)
	if err != nil {
		return nil, err
	}
	if err := into.UnmarshalBinary(tok.Payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}
	return tok, nil
}

func (b *Branca) encodeBytes(payload []byte) (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(b.rand, nonce); err != nil {
		return "", fmt.Errorf("libauth: generate nonce: %w", err)
	}

	now := b.now()
	if now.Unix() < 0 || now.Unix() > math.MaxUint32 {
		return "", fmt.Errorf("libauth: timestamp %d out of branca range (0..%d)", now.Unix(), int64(math.MaxUint32))
	}

	header := make([]byte, headerSize)
	header[0] = versionByte
	binary.BigEndian.PutUint32(header[1:5], uint32(now.Unix()))
	copy(header[5:], nonce)

	aead, err := chacha20poly1305.NewX(b.key)
	if err != nil {
		return "", err // unreachable: the key is exactly 32 bytes
	}
	sealed := aead.Seal(nil, nonce, payload, header)
	return base62Encode(append(header, sealed...)), nil
}

func (b *Branca) open(token string, ttl time.Duration) (*Token, error) {
	decoded, err := base62Decode(token)
	if err != nil {
		return nil, ErrTokenMalformed
	}
	if len(decoded) < minTokenLen {
		return nil, ErrTokenMalformed
	}
	if decoded[0] != versionByte {
		return nil, fmt.Errorf("%w: unsupported version 0x%02x", ErrTokenMalformed, decoded[0])
	}

	header := decoded[:headerSize]
	nonce := decoded[5:headerSize]
	timestamp := time.Unix(int64(binary.BigEndian.Uint32(decoded[1:5])), 0).UTC()

	aead, err := chacha20poly1305.NewX(b.key)
	if err != nil {
		return nil, err // unreachable: the key is exactly 32 bytes
	}
	payload, err := aead.Open(nil, nonce, decoded[headerSize:], header)
	if err != nil {
		return nil, ErrTokenInvalid
	}

	if ttl > 0 && b.now().After(timestamp.Add(ttl)) {
		return nil, fmt.Errorf("%w: issued at %s, ttl %s", ErrTokenExpired, timestamp.Format(time.RFC3339), ttl)
	}
	return &Token{Token: token, Timestamp: timestamp, Payload: payload}, nil
}
