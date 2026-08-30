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
//	err = b.Decode(token, 30*time.Minute, &session)
//
// Payloads are the caller's business — raw bytes in any format. Typed
// payloads encode themselves with the standard library
// encoding.BinaryMarshaler and encoding.BinaryUnmarshaler pair (see
// Payload); the payload type travels in the values, so no generic
// parameters are needed anywhere. Seal and Open handle raw bytes directly.
//
// VerifyBearer reads the "sub" member of a JSON payload and plugs straight
// into libauth.BearerIdentity:
//
//	// in the middleware:
//	libauth.BearerIdentity(b)
//
// Choose branca over jwt when the payload must stay confidential and one
// shared key already covers the whole trust domain; choose jwt (HS256 or
// Ed25519) when services must verify tokens without being able to create
// them, or when RFC 7519 interoperability matters.
package branca

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/binary"
	"encoding/json"
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

// Clock returns the current time. Inject one via WithNow to make sealing
// and age checks deterministic (mostly for tests).
type Clock func() time.Time

// Token is an opened branca token.
type Token struct {
	// Payload is the decrypted bytes the token was sealed with.
	Payload []byte

	// Timestamp is the creation time carried in the authenticated header.
	Timestamp time.Time
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

// Branca seals and opens branca tokens with one 32-byte key. A Branca is
// safe for concurrent use.
type Branca struct {
	key  []byte
	ttl  time.Duration
	now  Clock
	rand io.Reader
}

// Option customises a Branca.
type Option func(*Branca)

// WithTTL sets the token age VerifyBearer accepts. VerifyBearer refuses to
// run without it: bearer tokens must not be open-ended. Seal and Open are
// unaffected — their TTL is a per-call argument.
func WithTTL(d time.Duration) Option { return func(b *Branca) { b.ttl = d } }

// WithNow overrides the clock used for sealing and age checks. nil restores
// time.Now. Mostly useful in tests.
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

// Seal encrypts the payload (which may be empty) and returns the base62
// token. The current time is embedded in the authenticated header.
func (b *Branca) Seal(payload []byte) (string, error) {
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

// Open verifies and decrypts the token. When ttl > 0, tokens whose
// authenticated timestamp is older than ttl are rejected — after successful
// decryption, as the spec requires. Pass 0 to skip the age check.
func (b *Branca) Open(token string, ttl time.Duration) (*Token, error) {
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
	return &Token{Payload: payload, Timestamp: timestamp}, nil
}

// Encode marshals v with its MarshalBinary method and seals the bytes. The
// payload type is carried by v — no generic parameters involved.
func (b *Branca) Encode(v encoding.BinaryMarshaler) (string, error) {
	raw, err := v.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("libauth: marshal payload: %w", err)
	}
	return b.Seal(raw)
}

// Decode decrypts token and hands the payload to into's UnmarshalBinary —
// the json.Unmarshal shape, the payload type carried by the pointer you
// pass. Unmarshal failures surface as ErrTokenMalformed. The header
// timestamp is not returned; Open provides it.
func (b *Branca) Decode(token string, ttl time.Duration, into encoding.BinaryUnmarshaler) error {
	opened, err := b.Open(token, ttl)
	if err != nil {
		return err
	}
	if err := into.UnmarshalBinary(opened.Payload); err != nil {
		return fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}
	return nil
}

// VerifyBearer verifies token and returns the user ID its payload names —
// the adapter libauth.BearerIdentity expects. The payload convention is a
// JSON object with a string "sub" member; seal it with Encode and a
// type of your own. The Branca's WithTTL bounds the token age; without it
// VerifyBearer returns ErrMissingTTL.
func (b *Branca) VerifyBearer(token string) (string, error) {
	if b.ttl <= 0 {
		return "", ErrMissingTTL
	}
	opened, err := b.Open(token, b.ttl)
	if err != nil {
		return "", err
	}
	subject, err := jsonSub(opened.Payload)
	if err != nil {
		return "", err
	}
	if subject == "" {
		return "", ErrTokenWithoutSubject
	}
	return subject, nil
}

// jsonSub extracts the "sub" member of an identity payload: the payload
// must be a JSON object whose "sub", when present, is a string.
func jsonSub(payload []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}
	if decoder.More() {
		return "", fmt.Errorf("%w: trailing data after JSON object", ErrTokenMalformed)
	}
	member, ok := object["sub"]
	if !ok {
		return "", ErrTokenWithoutSubject
	}
	var subject string
	if err := json.Unmarshal(member, &subject); err != nil {
		return "", fmt.Errorf("%w: \"sub\" must be a string", ErrTokenMalformed)
	}
	return subject, nil
}
