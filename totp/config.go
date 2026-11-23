package totp

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"
)

// Algorithm identifies the HMAC hash used to derive codes.
type Algorithm string

// AlgorithmSHA1 is the only supported algorithm.
const AlgorithmSHA1 Algorithm = "SHA1"

// Clock returns the current time; inject one via WithNow in tests.
type Clock func() time.Time

// Defaults; New rejects any configuration that deviates from them.
const (
	// SecretSize is the RFC 4226 recommended 160-bit secret length.
	SecretSize = 20

	// KeySize is the exact AES-256 key length New requires.
	KeySize = 32

	DefaultPeriod        = 30 // seconds per step
	DefaultDigits        = 6
	DefaultSkew          = 1
	MaxSkew              = 1
	DefaultEnrollmentTTL = 10 * time.Minute
	DefaultAlgorithm     = AlgorithmSHA1
)

// Option customises an Authenticator. nil options are ignored.
type Option func(*settings)

type settings struct {
	issuer    string
	period    int
	digits    int
	algorithm Algorithm
	skew      int
	ttl       time.Duration
	now       Clock
	rand      io.Reader
}

func defaultSettings() *settings {
	return &settings{
		period:    DefaultPeriod,
		digits:    DefaultDigits,
		algorithm: DefaultAlgorithm,
		skew:      DefaultSkew,
		ttl:       DefaultEnrollmentTTL,
		now:       time.Now,
		rand:      rand.Reader,
	}
}

func newSettings(opts []Option) *settings {
	s := defaultSettings()
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// WithIssuer sets the issuer required by New; it must not contain ':'.
func WithIssuer(issuer string) Option { return func(s *settings) { s.issuer = issuer } }

// WithPeriod sets the step size in seconds. Only 30 is accepted.
func WithPeriod(period int) Option { return func(s *settings) { s.period = period } }

// WithDigits sets the code length. Only 6 is accepted.
func WithDigits(digits int) Option { return func(s *settings) { s.digits = digits } }

// WithAlgorithm sets the HMAC algorithm. Only SHA1 is accepted.
func WithAlgorithm(alg Algorithm) Option { return func(s *settings) { s.algorithm = alg } }

// WithSkew sets the accepted clock drift in steps (0 or 1, default 1).
func WithSkew(steps int) Option { return func(s *settings) { s.skew = steps } }

// WithEnrollmentTTL sets how long a pending enrollment stays activatable.
func WithEnrollmentTTL(ttl time.Duration) Option { return func(s *settings) { s.ttl = ttl } }

// WithNow overrides the clock; nil restores time.Now.
func WithNow(now Clock) Option {
	return func(s *settings) {
		if now == nil {
			now = time.Now
		}
		s.now = now
	}
}

// WithRand overrides the randomness source for secrets and nonces.
func WithRand(r io.Reader) Option {
	return func(s *settings) {
		if r != nil {
			s.rand = r
		}
	}
}

func (s *settings) validate() error {
	switch {
	case strings.TrimSpace(s.issuer) == "":
		return fmt.Errorf("%w: issuer is required", ErrInvalidConfig)
	case strings.ContainsRune(s.issuer, ':'):
		return fmt.Errorf("%w: issuer must not contain ':'", ErrInvalidConfig)
	case s.period != DefaultPeriod:
		return fmt.Errorf("%w: only a %d-second period is supported, got %d", ErrInvalidConfig, DefaultPeriod, s.period)
	case s.digits != DefaultDigits:
		return fmt.Errorf("%w: only %d-digit codes are supported, got %d", ErrInvalidConfig, DefaultDigits, s.digits)
	case s.algorithm != AlgorithmSHA1:
		return fmt.Errorf("%w: only the %s algorithm is supported, got %q", ErrInvalidConfig, AlgorithmSHA1, s.algorithm)
	case s.skew < 0 || s.skew > MaxSkew:
		return fmt.Errorf("%w: skew must be between 0 and %d, got %d", ErrInvalidConfig, MaxSkew, s.skew)
	case s.ttl <= 0:
		return fmt.Errorf("%w: enrollment TTL must be positive, got %s", ErrInvalidConfig, s.ttl)
	}
	return nil
}
