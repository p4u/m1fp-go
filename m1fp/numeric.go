package m1fp

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// settings for e‑voting -------------------------------------------------
const (
	VoteDigits = 9          // 10^9  >  100M · 64   (plenty of headroom)
	VoteMod    = 1000000000 // 10^9 as int
)

// EncryptVote encrypts a single ballot 0…64 using the compact
// “numeric‑only” encoding.  If r==nil a fresh randomizer is generated.
func EncryptVote(pk *PublicKey, vote uint64, r *big.Int) (*Ciphertext, *big.Int, error) {
	if vote > 64 {
		return nil, nil, fmt.Errorf("vote out of range")
	}
	msgDigits := fmt.Sprintf("%0*d", VoteDigits, vote) // 9‑digit zero‑pad
	return encryptDigits(pk, msgDigits, r)
}

// DecryptVote returns the numeric value encoded in a ciphertext produced
// by EncryptVote / Add.
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

// ----------------------------------------------------------------------
//
//  Low‑level helpers that operate directly on decimal strings
//
// ----------------------------------------------------------------------

// encryptDigits is identical to EncryptDeterministic except that the
// caller passes the decimal string directly (we skip asciiToDigits).
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
	prec := pk.Prec
	mod10n := pow10(n)

	// ---- step 1 : C1 -----------------------------------------------------
	xInt, _ := intFromFloat(pk.X, prec)
	c1Int := new(big.Int).Mul(r, xInt)
	mod2 := new(big.Int).Lsh(big.NewInt(1), prec)
	c1Int.Mod(c1Int, mod2)
	c1 := floatFromInt(c1Int, prec)

	// ---- step 2 : shared secret  r·h mod 1 ------------------------------
	hInt, _ := intFromFloat(pk.H, prec)
	Rint := new(big.Int).Mul(r, hInt)
	Rint.Mod(Rint, mod2)
	Rn := new(big.Int).Mul(Rint, mod10n)
	Rn.Div(Rn, mod2)

	// ---- step 3 : masking ----------------------------------------------
	Mint, _ := new(big.Int).SetString(msgDigits, 10)
	C2 := new(big.Int).Add(Mint, Rn)
	C2.Mod(C2, mod10n)

	C2Str := fmt.Sprintf("%0*d", n, C2)
	return &Ciphertext{C1: c1, C2: C2Str}, r, nil
}

// DecryptDigits returns the raw decimal string embedded in the
// ciphertext.  It is the inverse of encryptDigits.
func DecryptDigits(sk *PrivateKey, ct *Ciphertext) (string, error) {
	n := len(ct.C2)
	prec := sk.PK.Prec
	mod10n := pow10(n)

	// R' = a·C1  mod 1
	c1Int, _ := intFromFloat(ct.C1, prec)
	mod2 := new(big.Int).Lsh(big.NewInt(1), prec)
	Rint := new(big.Int).Mul(sk.A, c1Int)
	Rint.Mod(Rint, mod2)

	Rn := new(big.Int).Mul(Rint, mod10n)
	Rn.Div(Rn, mod2)

	C2int, _ := new(big.Int).SetString(ct.C2, 10)
	Mint := new(big.Int).Sub(C2int, Rn)
	if Mint.Sign() < 0 {
		Mint.Add(Mint, mod10n)
	}
	return fmt.Sprintf("%0*d", n, Mint), nil
}
