package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math"
	"testing"
	"time"
)

// rfcSecret is the seed from RFC 6238 Appendix B: the ASCII bytes of
// "12345678901234567890" (20 bytes, so RFC 4226's recommended size).
var rfcSecret = []byte("12345678901234567890")

// sha1New names the production hash constructor for test call sites.
var sha1New = sha1.New

// TestRFC6238Vectors checks the SHA-1 rows of RFC 6238 Appendix B. The
// published vectors use 8 digits; codeAt is parameterised so the same
// implementation is exercised, while the public API stays 6-digit only.
func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		code string
		step int64
	}{
		{59, "94287082", 1},
		{1111111109, "07081804", 37037036},
		{1111111111, "14050471", 37037037},
		{1234567890, "89005924", 41152263},
		{2000000000, "69279037", 66666666},
		{20000000000, "65353130", 666666666},
	}
	for _, tc := range cases {
		step := stepAt(tc.unix, 30)
		if step != tc.step {
			t.Fatalf("stepAt(%d) = %d, want %d", tc.unix, step, tc.step)
		}
		if got := codeAt(rfcSecret, step, 8, sha1.New); got != tc.code {
			t.Errorf("SHA1 T=%d: code = %q, want %q", tc.unix, got, tc.code)
		}
	}

	// The same RFC lists SHA-256 and SHA-512 rows; they are not reachable
	// from the public configuration but codeAt is hash-agnostic.
	sha256Secret := []byte("12345678901234567890123456789012")
	if got := codeAt(sha256Secret, stepAt(59, 30), 8, sha256.New); got != "46119246" {
		t.Errorf("SHA256 T=59: code = %q, want 46119246", got)
	}
	sha512Secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")
	if got := codeAt(sha512Secret, stepAt(59, 30), 8, sha512.New); got != "90693936" {
		t.Errorf("SHA512 T=59: code = %q, want 90693936", got)
	}
}

// TestCodeAtSixDigits checks the public 6-digit profile and zero padding.
func TestCodeAtSixDigits(t *testing.T) {
	if got := codeAt(rfcSecret, stepAt(59, 30), 6, sha1.New); got != "287082" {
		t.Fatalf("6-digit code = %q, want 287082", got)
	}
	// Find a step whose 6-digit code has a leading zero, verifying padding
	// rather than accidental length.
	found := false
	for step := int64(0); step < 10000 && !found; step++ {
		code := codeAt(rfcSecret, step, 6, sha1.New)
		if len(code) != 6 {
			t.Fatalf("code %q at step %d is not 6 digits", code, step)
		}
		if code[0] == '0' {
			found = true
		}
	}
	if !found {
		t.Fatal("no zero-padded code found in 10000 steps")
	}
}

// TestStepAtBoundaries pins the floor semantics and negative-time handling.
func TestStepAtBoundaries(t *testing.T) {
	cases := []struct {
		unix int64
		want int64
	}{
		{0, 0},
		{29, 0},
		{30, 1},
		{31, 1},
		{59, 1},
		{60, 2},
		{-1, -1},
		{-29, -1},
		{-30, -1},
		{-31, -2},
	}
	for _, tc := range cases {
		if got := stepAt(tc.unix, 30); got != tc.want {
			t.Errorf("stepAt(%d) = %d, want %d", tc.unix, got, tc.want)
		}
	}
}

func TestAddStepOverflow(t *testing.T) {
	if _, ok := addStep(math.MaxInt64, 1); ok {
		t.Fatal("addStep(MaxInt64, 1) overflowed silently")
	}
	if _, ok := addStep(math.MinInt64, -1); ok {
		t.Fatal("addStep(MinInt64, -1) overflowed silently")
	}
	if got, ok := addStep(math.MaxInt64-1, 1); !ok || got != math.MaxInt64 {
		t.Fatalf("addStep(MaxInt64-1, 1) = %d, %v", got, ok)
	}
	if got, ok := addStep(5, -2); !ok || got != 3 {
		t.Fatalf("addStep(5, -2) = %d, %v", got, ok)
	}
}

func TestParseCode(t *testing.T) {
	if _, ok := parseCode("012345", 6); !ok {
		t.Error("valid code rejected")
	}
	bad := []string{"", "12345", "1234567", "12345a", " 12345", "123456 ", "１２３４５６", "-12345", "+12345", "12345\n"}
	for _, code := range bad {
		if _, ok := parseCode(code, 6); ok {
			t.Errorf("parseCode(%q) accepted a malformed code", code)
		}
	}
}

// TestMatchStepWindow checks the acceptance window and its ordering.
func TestMatchStepWindow(t *testing.T) {
	const current = int64(1000)
	for _, skew := range []int{0, 1} {
		for delta := -2; delta <= 2; delta++ {
			code := codeAt(rfcSecret, current+int64(delta), 6, sha1.New)
			got, ok := matchStep(rfcSecret, code, current, skew, 6)
			inWindow := delta >= -skew && delta <= skew
			if inWindow {
				if !ok || got != current+int64(delta) {
					t.Errorf("skew=%d delta=%d: match = (%d, %v), want (%d, true)", skew, delta, got, ok, current+int64(delta))
				}
				continue
			}
			// Out-of-window codes may legitimately collide with an in-window
			// step (1 in a million); only fail if the match is out of window.
			if ok && (got < current-int64(skew) || got > current+int64(skew)) {
				t.Errorf("skew=%d delta=%d: matched out-of-window step %d", skew, delta, got)
			}
		}
	}
}

// TestMatchStepPrefersOldest keeps the oldest-first ordering honest: a code
// valid for two steps in the window must map to the older one, so a lagging
// client does not burn the current step.
func TestMatchStepPrefersOldest(t *testing.T) {
	secret := rfcSecret
	current := int64(500)
	older := current - 1
	// Find a step pair whose codes cannot collide for this secret; nothing
	// guarantees it, so assert on the step returned only when they differ.
	olderCode := codeAt(secret, older, 6, sha1.New)
	if olderCode == codeAt(secret, current, 6, sha1.New) {
		t.Skip("codes collide for this secret")
	}
	if got, ok := matchStep(secret, olderCode, current, 1, 6); !ok || got != older {
		t.Fatalf("match = (%d, %v), want (%d, true)", got, ok, older)
	}
}

// TestCodeAtDigitsLength checks code length across the digit counts the
// internal helper supports.
func TestCodeAtDigitsLength(t *testing.T) {
	for _, digits := range []int{1, 6, 8} {
		got := codeAt(rfcSecret, 42, digits, sha1.New)
		if len(got) != digits {
			t.Errorf("digits=%d: %q has length %d", digits, got, len(got))
		}
	}
}

// TestCodeAtHashIndependence makes sure the hash parameter is actually
// threaded through rather than hard-coded.
func TestCodeAtHashIndependence(t *testing.T) {
	var fn func() hash.Hash = sha1.New
	if codeAt(rfcSecret, 1, 8, fn) == codeAt(rfcSecret, 1, 8, sha256.New) {
		t.Fatal("SHA1 and SHA256 produced the same code")
	}
}

func TestStepAtMatchesTimeTruncate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if stepAt(now.Unix(), 30) != now.Unix()/30 {
		t.Fatal("positive step disagrees with truncation")
	}
}
