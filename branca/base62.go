package branca

import (
	"errors"
	"math/big"
)

// base62Alphabet is the character set the branca spec mandates: digits,
// then uppercase, then lowercase.
const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var base62Index = func() (idx [256]int8) {
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(base62Alphabet); i++ {
		idx[base62Alphabet[i]] = int8(i)
	}
	return idx
}()

var errNonBase62 = errors.New("libauth: token contains a non-base62 character")

var (
	base62Radix = big.NewInt(62)
	base62Digit = new(big.Int)
)

// base62Encode treats the token bytes as one big-endian integer and
// converts the whole thing (the same numeric conversion every conformant
// implementation uses). Leading zero bytes cannot occur: the version byte
// 0xBA is always first.
func base62Encode(src []byte) string {
	if len(src) == 0 {
		return ""
	}
	n := new(big.Int).SetBytes(src)
	digits := make([]byte, 0, 64)
	rem := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, base62Radix, rem)
		digits = append(digits, base62Alphabet[rem.Int64()])
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

// base62Decode parses a base62 token. Invalid characters — including sign
// prefixes big.Int would otherwise accept — are rejected.
func base62Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errNonBase62
	}
	n := new(big.Int)
	for i := 0; i < len(s); i++ {
		d := base62Index[s[i]]
		if d < 0 {
			return nil, errNonBase62
		}
		n.Mul(n, base62Radix)
		base62Digit.SetInt64(int64(d))
		n.Add(n, base62Digit)
	}
	return n.Bytes(), nil
}