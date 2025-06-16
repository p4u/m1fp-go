package m1fp

import (
	"fmt"
	"math/big"
)

// Add performs homomorphic addition of two ciphertexts in the common domain.
// The operation is simplified to pure modular arithmetic without carry logic,
// thanks to the unified domain D = 2^P · 5^n approach.
//
// Both ciphertexts must use the same common denominator D for compatibility.
// The precision parameter is maintained for API compatibility but is not used
// in the common domain implementation.
func (c *Ciphertext) Add(other *Ciphertext, prec uint16) (*Ciphertext, error) {
	if c == nil || other == nil || c.c1 == nil || other.c1 == nil {
		return nil, fmt.Errorf("nil ciphertext")
	}
	if c.d == nil || other.d == nil {
		return nil, fmt.Errorf("missing common denominator")
	}
	if c.d.Cmp(other.d) != 0 {
		return nil, fmt.Errorf("mismatched common denominators")
	}

	sumC1 := new(big.Int).Add(c.c1, other.c1)
	sumC1.Mod(sumC1, c.d)

	sumC2 := new(big.Int).Add(c.c2, other.c2)
	sumC2.Mod(sumC2, c.d)

	n := max(other.n, c.n)

	return &Ciphertext{c1: sumC1, c2: sumC2, d: new(big.Int).Set(c.d), n: n}, nil
}

// AddMany performs homomorphic addition of multiple ciphertexts.
// Efficiently combines multiple encrypted values into a single ciphertext
// representing their sum, maintaining perfect precision throughout.
func AddMany(prec uint16, cts ...*Ciphertext) (*Ciphertext, error) {
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
