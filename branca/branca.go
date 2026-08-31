// Package branca implements the branca token specification
// (https://github.com/tuupola/branca-spec): authenticated, encrypted API
// tokens built on IETF XChaCha20-Poly1305 AEAD, base62 encoded.
//
// A branca token is opaque: the payload is encrypted, not merely signed,
// so only holders of the 32-byte key can read it. The wire format is
//
//	Version (0xBA) || Timestamp (4B) || Nonce (24B) || Ciphertext || Tag (16B)
//
// with the header authenticated as the AEAD's additional data. The header
// timestamp is what consumers check against a TTL at open time — the
// issuing side cannot fix an expiry into the token, and the same token may
// carry different validity windows for different consumers.
//
// The token format and crypto come from the specification; the AEAD
// primitive is golang.org/x/crypto/chacha20poly1305 (Go's audited
// implementation). This is the only dependency the libauth core and jwt
// packages do not have.
//
//	b, err := branca.New(key)
//
//	token, err := b.Encode(Session{Sub: "bob"})
//
//	var session Session
//	tok, err := b.Decode(token, 30*time.Minute, &session)
//	_ = tok.Timestamp // from the authenticated header
//
// Payloads are the caller's business — anything implementing the standard
// library encoding.BinaryMarshaler / encoding.BinaryUnmarshaler pair. The
// payload type travels in the value, so no generic parameters are needed.
// Raw byte payloads can use Bytes directly.
//
// Choose branca over jwt when the payload must stay confidential and one
// shared key already covers the whole trust domain; choose jwt (HS256 or
// Ed25519) when services must verify tokens without being able to create
// them, or when RFC 7519 interoperability matters.
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
	// KeySize is the exact key length branca requires: 32 bytes.
	KeySize = chacha20poly1305.KeySize

	versionByte = 0xBA
	nonceSize   = 24
	headerSize  = 1 + 4 + nonceSize // version || timestamp || nonce
	tagSize     = 16
	minTokenLen = headerSize + tagSize
)

// Clock returns the current time. Inject one via WithNow to make encoding
// and age checks deterministic (mostly for tests).
type Clock func() time.Time

// Token is the decoded form of a branca token. Timestamp comes from the
// authenticated header. Payload is the decrypted bytes; Decode hands it
// to the unmarshaler for you but also exposes it for callers that want
// the raw bytes.
type Token struct {
	Token     string
	Timestamp time.Time
	Payload   []byte
}

// Bytes is a raw-byte payload — a convenience for callers that do not have
// a typed encoding.BinaryMarshaler:
//
//	token, _ := b.Encode(branca.Bytes("Hello world!"))
//	var got branca.Bytes
//	b.Decode(token, 0, &got)  // got == "Hello world!"
type Bytes []byte

// MarshalBinary implements encoding.BinaryMarshaler.
func (b Bytes) MarshalBinary() ([]byte, error) { return b, nil }

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (b *Bytes) UnmarshalBinary(raw []byte) error {
	*b = append((*b)[:0], raw...)
	return nil
}

// Payload is the pair of standard library interfaces typed payloads
// implement — encoding.BinaryMarshaler plus encoding.BinaryUnmarshaler.
// Implement MarshalBinary on the value and UnmarshalBinary on the pointer,
// then pin it down with the canonical compile-time check:
//
//	var _ branca.Payload = (*Session)(nil)
type Payload interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// Branca encodes and decodes branca tokens with one 32-byte key. A Branca
// is safe for concurrent use.
type Branca struct {
	key  []byte
	now  Clock
	rand io.Reader
}

// Option customises a Branca.
type Option func(*Branca)

// WithNow overrides the clock used for encoding and age checks. nil
// restores time.Now. Mostly useful in tests.
func WithNow(now Clock) Option {
	return func(b *Branca) {
		if now != nil {
			b.now = now
		}
	}
}

// WithRand overrides the randomness source nonces are drawn from. nil
// restores crypto/rand.Reader. Mostly useful in tests.
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

// Encode encrypts v under the key and returns the resulting token. The
// current time is embedded in the authenticated header. The payload type
// is carried by v — no generic parameters involved.
func (b *Branca) Encode(v encoding.BinaryMarshaler) (string, error) {
	raw, err := v.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("libauth: marshal payload: %w", err)
	}
	return b.encodeBytes(raw)
}

// Decode verifies the token, decrypts the payload and hands it to into's
// UnmarshalBinary. The returned Token carries the authenticated timestamp
// and the raw payload bytes (handy for callers that want both the typed
// value and the original bytes). Unmarshal failures surface as
// ErrTokenMalformed. When ttl > 0, tokens whose authenticated timestamp
// is older than ttl are rejected — after successful decryption, as the
// spec requires. Pass 0 to skip the age check.
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

// encodeBytes encrypts an already-marshalled payload under the AEAD.
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

// open verifies and decrypts the token, returning a fully populated Token
// (including the decrypted payload) or one of the package's sentinel
// errors. The TTL check, when ttl > 0, runs after successful decryption.
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