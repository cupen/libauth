package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"hash"
	"math"
	"strconv"
	"strings"
)

// stepAt converts a Unix timestamp into a TOTP step number, rounding toward
// negative infinity. Floor semantics matter for pre-epoch timestamps: Go's
// integer division truncates toward zero, which would put -1 second in the
// same step as +1 second.
func stepAt(unix int64, period int64) int64 {
	step := unix / period
	if unix%period < 0 {
		step--
	}
	return step
}

// addStep adds delta to step, reporting false when the result would overflow
// int64. Real timestamps are nowhere near these limits; the guard keeps
// crafted clocks from wrapping the acceptance window.
func addStep(step, delta int64) (int64, bool) {
	switch {
	case delta > 0 && step > math.MaxInt64-delta:
		return 0, false
	case delta < 0 && step < math.MinInt64-delta:
		return 0, false
	}
	return step + delta, true
}

// codeAt computes the RFC 4226 HOTP value for step, with RFC 4226 dynamic
// truncation. h parameterises the hash so tests can run the RFC 6238
// SHA-1 vectors at 8 digits; production callers always use SHA-1 at 6.
// Callers must pass 1 <= digits <= 10.
func codeAt(secret []byte, step int64, digits int, h func() hash.Hash) string {
	mac := hmac.New(h, secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := strconv.FormatUint(uint64(value)%mod, 10)
	if pad := digits - len(code); pad > 0 {
		code = strings.Repeat("0", pad) + code
	}
	return code
}

// parseCode validates a user-supplied code. Only ASCII digits of exactly
// digits length are accepted; the value is never parsed into an integer, so
// nothing can overflow. The returned string is safe to compare in constant
// time.
func parseCode(code string, digits int) (string, bool) {
	if len(code) != digits {
		return "", false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return "", false
		}
	}
	return code, true
}

// matchStep searches the acceptance window oldest-step-first and returns the
// matching step. Trying older steps first means a user whose clock lags one
// step consumes the older step, leaving the current step usable on the next
// attempt.
func matchStep(secret []byte, code string, current int64, skew, digits int) (int64, bool) {
	want := []byte(code)
	for delta := -skew; delta <= skew; delta++ {
		step, ok := addStep(current, int64(delta))
		if !ok {
			continue
		}
		got := codeAt(secret, step, digits, sha1.New)
		if subtle.ConstantTimeCompare([]byte(got), want) == 1 {
			return step, true
		}
	}
	return 0, false
}
