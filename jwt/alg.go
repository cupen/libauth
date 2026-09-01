package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

var b64 = base64.RawURLEncoding

func b64encode(b []byte) string { return b64.EncodeToString(b) }
func b64decode(s string) ([]byte, error) { return b64.DecodeString(s) }

// algorithm is the pinned signing scheme behind a Signer or Verifier. Each
// implementation covers exactly one JOSE alg value, which is how
// cross-algorithm confusion is ruled out structurally.
type algorithm interface {
	name() string
	header() []byte
	sign(input []byte) ([]byte, error)
	verify(input, sig []byte) error
}

// minHMACKeySize is the SHA-256 output size; RFC 7518 §3.2 says HS256 keys
// SHOULD have at least this many bytes.
const minHMACKeySize = 32

type hmacAlg struct {
	algName string
	key     []byte
}

func newHMACAlg(name string, key []byte) (hmacAlg, error) {
	if len(key) < minHMACKeySize {
		return hmacAlg{}, fmt.Errorf("%w: HS256 key must be at least %d bytes, got %d", ErrInvalidKey, minHMACKeySize, len(key))
	}
	return hmacAlg{algName: name, key: bytes.Clone(key)}, nil
}

func (a hmacAlg) name() string   { return a.algName }
func (a hmacAlg) header() []byte { return []byte(`{"alg":"` + a.algName + `","typ":"JWT"}`) }

func (a hmacAlg) sign(input []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, a.key)
	mac.Write(input)
	return mac.Sum(nil), nil
}

func (a hmacAlg) verify(input, sig []byte) error {
	mac := hmac.New(sha256.New, a.key)
	mac.Write(input)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return ErrTokenBadSignature
	}
	return nil
}

type eddsaAlg struct {
	priv ed25519.PrivateKey // nil for verify-only instances
	pub  ed25519.PublicKey
}

func newEdDSASignAlg(key ed25519.PrivateKey) (eddsaAlg, error) {
	if len(key) != ed25519.PrivateKeySize {
		return eddsaAlg{}, fmt.Errorf("%w: Ed25519 private key must be %d bytes, got %d", ErrInvalidKey, ed25519.PrivateKeySize, len(key))
	}
	priv := ed25519.PrivateKey(bytes.Clone(key))
	return eddsaAlg{
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}, nil
}

func newEdDSAVerifyAlg(key ed25519.PublicKey) (eddsaAlg, error) {
	if len(key) != ed25519.PublicKeySize {
		return eddsaAlg{}, fmt.Errorf("%w: Ed25519 public key must be %d bytes, got %d", ErrInvalidKey, ed25519.PublicKeySize, len(key))
	}
	return eddsaAlg{pub: ed25519.PublicKey(bytes.Clone(key))}, nil
}

func (a eddsaAlg) name() string   { return AlgEdDSA }
func (a eddsaAlg) header() []byte { return []byte(`{"alg":"EdDSA","typ":"JWT"}`) }

func (a eddsaAlg) sign(input []byte) ([]byte, error) {
	if len(a.priv) == 0 {
		return nil, fmt.Errorf("%w: signing requires an Ed25519 private key", ErrInvalidKey)
	}
	return ed25519.Sign(a.priv, input), nil
}

func (a eddsaAlg) verify(input, sig []byte) error {
	if !ed25519.Verify(a.pub, input, sig) {
		return ErrTokenBadSignature
	}
	return nil
}