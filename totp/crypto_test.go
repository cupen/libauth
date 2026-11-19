package totp

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

func TestNewSecretCipherKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := newSecretCipher(make([]byte, n), nil); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("newSecretCipher(%d bytes): err = %v, want ErrInvalidConfig", n, err)
		}
	}
	if _, err := newSecretCipher(make([]byte, KeySize), nil); err != nil {
		t.Fatalf("newSecretCipher(32 bytes): %v", err)
	}
}

func TestSecretCipherRoundTrip(t *testing.T) {
	c, err := newSecretCipher(testKey(t), nil)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	secret := []byte("twenty-byte-secret!!")[:SecretSize]
	sealed, err := c.seal("alice", secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("plaintext secret appears in the ciphertext")
	}
	opened, err := c.open("alice", sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatalf("open = %q, want %q", opened, secret)
	}
}

func TestSecretCipherRandomisedNonce(t *testing.T) {
	c, err := newSecretCipher(testKey(t), nil)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	secret := bytes.Repeat([]byte{7}, SecretSize)
	first, err := c.seal("alice", secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	second, err := c.seal("alice", secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("sealing the same secret twice produced identical ciphertext")
	}
}

// TestSecretCipherBindsUserID proves the AAD binding: a ciphertext moved to
// another user is undecryptable.
func TestSecretCipherBindsUserID(t *testing.T) {
	c, err := newSecretCipher(testKey(t), nil)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	sealed, err := c.seal("alice", bytes.Repeat([]byte{1}, SecretSize))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := c.open("bob", sealed); err == nil {
		t.Fatal("ciphertext decrypted under a different user ID")
	}
}

func TestSecretCipherTamper(t *testing.T) {
	c, err := newSecretCipher(testKey(t), nil)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	sealed, err := c.seal("alice", bytes.Repeat([]byte{2}, SecretSize))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for i := range sealed {
		tampered := append([]byte(nil), sealed...)
		tampered[i] ^= 0x01
		if _, err := c.open("alice", tampered); err == nil {
			t.Fatalf("flipping byte %d still decrypted", i)
		}
	}
	if _, err := c.open("alice", sealed[:c.aead.NonceSize()]); err == nil {
		t.Fatal("truncated ciphertext decrypted")
	}
	if _, err := c.open("alice", nil); err == nil {
		t.Fatal("empty ciphertext decrypted")
	}
}

func TestSecretCipherWrongKey(t *testing.T) {
	sealer, err := newSecretCipher(testKey(t), nil)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	sealed, err := sealer.seal("alice", bytes.Repeat([]byte{3}, SecretSize))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	other, err := newSecretCipher(testKey(t), nil)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	if _, err := other.open("alice", sealed); err == nil {
		t.Fatal("ciphertext decrypted under a different key")
	}
}

func TestSecretCipherNonceFailure(t *testing.T) {
	c, err := newSecretCipher(make([]byte, KeySize), failingReader{})
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	if _, err := c.seal("alice", bytes.Repeat([]byte{4}, SecretSize)); !errors.Is(err, errReaderBoom) {
		t.Fatalf("seal with failing reader: err = %v, want errReaderBoom", err)
	}
}

var errReaderBoom = errors.New("entropy source failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errReaderBoom }

// TestSecretCipherNilRandFallsBack covers WithRand(nil) semantics and the
// zero-value guard inside newSecretCipher.
func TestSecretCipherNilRandFallsBack(t *testing.T) {
	c, err := newSecretCipher(make([]byte, KeySize), nil)
	if err != nil {
		t.Fatalf("newSecretCipher: %v", err)
	}
	if c.rand == nil {
		t.Fatal("nil reader was not replaced by crypto/rand")
	}
	var _ io.Reader = c.rand
	sealed, err := c.seal("alice", []byte("secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("seal returned no ciphertext")
	}
}
