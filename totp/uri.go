package totp

import (
	"fmt"
	"strconv"
	"strings"
)

// buildURI renders the otpauth:// URI for a TOTP enrollment.
//
// Format (Key Uri Format used by Google Authenticator and compatible apps):
//
//	otpauth://totp/{issuer}:{account}?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
//
// The label and every query value are percent-encoded with the same strict
// RFC 3986 encoder, so a space becomes %20 rather than '+'. A colon inside
// the raw issuer or account would make the label ambiguous, so it is
// rejected rather than encoded: the spec reserves ':' as the label
// separator.
func buildURI(issuer, account, secret string, digits, period int) (string, error) {
	if strings.ContainsRune(account, ':') {
		return "", fmt.Errorf("%w: account name must not contain ':'", ErrInvalidConfig)
	}
	if strings.ContainsRune(issuer, ':') {
		return "", fmt.Errorf("%w: issuer must not contain ':'", ErrInvalidConfig)
	}
	label := percentEncode(issuer) + ":" + percentEncode(account)

	// Fixed parameter order keeps the URI stable across calls and releases.
	query := "secret=" + percentEncode(secret) +
		"&issuer=" + percentEncode(issuer) +
		"&algorithm=" + percentEncode(string(AlgorithmSHA1)) +
		"&digits=" + strconv.Itoa(digits) +
		"&period=" + strconv.Itoa(period)

	return "otpauth://totp/" + label + "?" + query, nil
}

// percentEncode escapes everything outside RFC 3986's unreserved set. It is
// stricter than url.PathEscape, which would leave reserved characters such
// as '@' and ':' unescaped.
func percentEncode(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperhex[c>>4])
		b.WriteByte(upperhex[c&0x0f])
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	}
	return false
}
