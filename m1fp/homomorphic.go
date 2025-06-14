package m1fp

import (
	"fmt"
	"math/big"
)

// Add homomorphically adds two ciphertexts.
// It now propagates the carry that may arise from the fractional‑part
// addition into the decimal‑masked component.
// This version uses exact integer arithmetic to avoid float precision issues.
func (c *Ciphertext) Add(other *Ciphertext, prec uint) (*Ciphertext, error) {
	if c == nil || other == nil || c.c1Int == nil || other.c1Int == nil {
		return nil, fmt.Errorf("nil ciphertext")
	}
	if prec == 0 {
		return nil, fmt.Errorf("invalid precision")
	}

	//------------------------------------------------------------------//
	// 1)  Exact fixed‑point addition of C1  (mod 2^prec) - pure integer
	//------------------------------------------------------------------//
	mod2 := new(big.Int).Lsh(big.NewInt(1), prec)    // 2^prec
	sumInt := new(big.Int).Add(c.c1Int, other.c1Int) // exact integer addition
	carry := sumInt.Cmp(mod2) >= 0                   // did we wrap?
	if carry {
		sumInt.Sub(sumInt, mod2)
	}

	//------------------------------------------------------------------//
	// 2)  Integer addition of C2, with the fractional carry
	//------------------------------------------------------------------//
	if c.n%3 != 0 || other.n%3 != 0 {
		return nil, fmt.Errorf("malformed C2 digit counts (n %% 3 ≠ 0)")
	}
	n := max(other.n, c.n)
	if r := n % 3; r != 0 {
		n += 3 - r
	}

	// Direct integer addition - no string conversions needed
	sumC2 := new(big.Int).Add(c.c2Int, other.c2Int)
	if carry {
		sumC2.Add(sumC2, big.NewInt(1))
	}

	mod10n := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	sumC2.Mod(sumC2, mod10n)

	return &Ciphertext{c1Int: sumInt, c2Int: sumC2, n: n}, nil
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
