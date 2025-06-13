package m1fp

import (
	"fmt"
	"math/big"
	"strings"
)

// Add homomorphically adds two ciphertexts.
// It now propagates the carry that may arise from the fractional‑part
// addition into the decimal‑masked component.
func (c *Ciphertext) Add(other *Ciphertext, prec uint) (*Ciphertext, error) {
	if c == nil || other == nil || c.C1 == nil || other.C1 == nil {
		return nil, fmt.Errorf("nil ciphertext")
	}
	if prec == 0 {
		return nil, fmt.Errorf("invalid precision")
	}

	//------------------------------------------------------------------//
	// 1)  Exact fixed‑point addition of C1  (mod 2^prec)
	//------------------------------------------------------------------//
	i1, err := intFromFloat(c.C1, prec)
	if err != nil {
		return nil, fmt.Errorf("C1 decode: %w", err)
	}
	i2, err := intFromFloat(other.C1, prec)
	if err != nil {
		return nil, fmt.Errorf("C1′ decode: %w", err)
	}

	mod2 := new(big.Int).Lsh(big.NewInt(1), prec) // 2^prec
	sumInt := new(big.Int).Add(i1, i2)            // i1 + i2
	carry := sumInt.Cmp(mod2) >= 0                // did we wrap?
	if carry {
		sumInt.Sub(sumInt, mod2)
	}
	sumC1 := floatFromInt(sumInt, prec)

	//------------------------------------------------------------------//
	// 2)  Integer addition of C2, with the fractional carry
	//------------------------------------------------------------------//
	aStr, bStr := c.C2, other.C2
	if len(aStr)%3 != 0 || len(bStr)%3 != 0 {
		return nil, fmt.Errorf("malformed C2 strings (len %% 3 ≠ 0)")
	}
	n := len(aStr)
	if len(bStr) > n {
		n = len(bStr)
	}
	if r := n % 3; r != 0 {
		n += 3 - r
	}

	aStr = strings.Repeat("0", n-len(aStr)) + aStr
	bStr = strings.Repeat("0", n-len(bStr)) + bStr

	ai, _ := new(big.Int).SetString(aStr, 10)
	bi, _ := new(big.Int).SetString(bStr, 10)

	sumC2 := new(big.Int).Add(ai, bi)
	if carry {
		sumC2.Add(sumC2, big.NewInt(1))
	}

	mod10n := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	sumC2.Mod(sumC2, mod10n)

	sumC2Str := fmt.Sprintf("%0*d", n, sumC2) // zero‑pad
	return &Ciphertext{C1: sumC1, C2: sumC2Str}, nil
}

// AddMany unchanged.
func AddMany(prec uint, cts ...*Ciphertext) (*Ciphertext, error) {
	if len(cts) == 0 {
		return nil, fmt.Errorf("no ciphertexts")
	}
	acc := cts[0]
	var err error
	for i := 1; i < len(cts); i++ {
		acc, err = acc.Add(cts[i], prec)
		if err != nil {
			return nil, err
		}
	}
	return acc, nil
}
