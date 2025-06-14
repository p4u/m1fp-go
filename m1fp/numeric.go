package m1fp

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// VoteDigits defines the number of decimal digits used for vote encoding.
// This provides sufficient range for large-scale elections (10^9 > 100M votes).
const (
	VoteDigits = 9          // Maximum decimal digits for vote representation
	VoteMod    = 1000000000 // 10^9 modulus for vote arithmetic
)

// EncryptVote encrypts a single numeric vote using the common domain approach.
// The vote value must be in the range [0, 64] for compatibility with the voting system.
// If r is nil, a fresh random value is generated for probabilistic encryption.
func EncryptVote(pk *PublicKey, vote uint64, r *big.Int) (*Ciphertext, *big.Int, error) {
	if vote > 64 {
		return nil, nil, fmt.Errorf("vote out of range")
	}
	msgDigits := fmt.Sprintf("%0*d", VoteDigits, vote)
	return encryptDigits(pk, msgDigits, r)
}

// DecryptVote recovers the numeric value from a ciphertext produced by EncryptVote.
// Returns the original vote value as an unsigned integer.
func DecryptVote(sk *PrivateKey, ct *Ciphertext) (uint64, error) {
	plain, err := DecryptDigits(sk, ct)
	if err != nil {
		return 0, err
	}
	i, ok := new(big.Int).SetString(plain, 10)
	if !ok {
		return 0, fmt.Errorf("invalid decimal in plaintext")
	}
	return i.Uint64(), nil
}

// encryptDigits encrypts a decimal string using the common domain approach.
// This internal function handles the core encryption logic for numeric values,
// ensuring all arithmetic is performed in the unified domain D = 2^P · 5^n.
func encryptDigits(pk *PublicKey, msgDigits string, r *big.Int) (*Ciphertext, *big.Int, error) {
	if r == nil {
		var err error
		r, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, nil, err
		}
		if r.Sign() == 0 {
			r.Add(r, big.NewInt(1))
		}
	}
	n := len(msgDigits)

	if n != VoteDigits {
		if n > VoteDigits {
			return nil, nil, fmt.Errorf("message too long: %d digits, max %d", n, VoteDigits)
		}
		msgDigits = fmt.Sprintf("%0*s", VoteDigits, msgDigits)
		n = VoteDigits
	}

	if pk.Prec < uint(n) {
		return nil, nil, fmt.Errorf("precision %d too small for %d digits", pk.Prec, n)
	}

	messageInt, _ := new(big.Int).SetString(msgDigits, 10)
	scaleFactor := new(big.Int).Lsh(big.NewInt(1), pk.Prec-uint(n))
	M := new(big.Int).Mul(messageInt, scaleFactor)

	c1 := new(big.Int).Mul(r, pk.XInt)
	c1.Mod(c1, pk.D)

	rH := new(big.Int).Mul(r, pk.HInt)
	rH.Mod(rH, pk.D)

	c2 := new(big.Int).Add(M, rH)
	c2.Mod(c2, pk.D)

	return &Ciphertext{c1: c1, c2: c2, d: new(big.Int).Set(pk.D), n: uint(n)}, r, nil
}

// DecryptDigits recovers the raw decimal string from a ciphertext.
// This internal function performs the inverse of encryptDigits, maintaining
// precision through the common domain approach and proper rounding.
func DecryptDigits(sk *PrivateKey, ct *Ciphertext) (string, error) {
	if ct.d == nil {
		return "", fmt.Errorf("missing common denominator in ciphertext")
	}

	n := ct.n
	if sk.PK.Prec < uint(n) {
		return "", fmt.Errorf("precision %d too small for %d digits", sk.PK.Prec, n)
	}

	aC1 := new(big.Int).Mul(sk.A, ct.c1)
	aC1.Mod(aC1, ct.d)

	MPrime := new(big.Int).Sub(ct.c2, aC1)
	if MPrime.Sign() < 0 {
		MPrime.Add(MPrime, ct.d)
	}

	scaleFactor := new(big.Int).Lsh(big.NewInt(1), sk.PK.Prec-uint(n))
	messageInt := new(big.Int)
	remainder := new(big.Int)
	messageInt.DivMod(MPrime, scaleFactor, remainder)

	if remainder.Sign() != 0 {
		halfScale := new(big.Int).Div(scaleFactor, big.NewInt(2))
		if remainder.Cmp(halfScale) >= 0 {
			messageInt.Add(messageInt, big.NewInt(1))
		}
	}

	return fmt.Sprintf("%0*d", int(n), messageInt), nil
}
