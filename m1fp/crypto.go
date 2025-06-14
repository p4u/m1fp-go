// Package m1fp implements the public–key encryption scheme
// proposed by El‑Yahyaoui & Omary (2022).  Security rests on the
// Modulo‑1 Factoring Problem (M1FP), believed NP‑hard and
// resistant to quantum attacks.
//
// All arithmetic uses exact integer operations for precision and
// performance. The caller chooses the working precision when generating keys.
package m1fp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const X = "0.6094379124341003746007593332261876395256013542685177219126478914741789877076578"

// PrivateKey = {a, pk}.  The secret integer a is never exposed.
type PrivateKey struct {
	A  *big.Int
	PK PublicKey
}

// KeyGen creates a fresh key pair.
//
//	precBits  – arithmetic precision (≥ 128; 256 is a safe default)
//	xString   – textual representation of an irrational  0 < x < 1  (e.g. "0.6094379124")
//
// Returns (sk, pk, error).
func KeyGen(precBits uint, xString string) (*PrivateKey, *PublicKey, error) {
	if precBits < 128 {
		return nil, nil, fmt.Errorf("precision too small")
	}
	x, ok := new(big.Float).SetPrec(precBits).SetString(xString)
	if !ok {
		return nil, nil, fmt.Errorf("invalid x string")
	}
	// 1 > x > 0 ?
	if x.Sign() <= 0 || x.Cmp(big.NewFloat(1).SetPrec(precBits)) >= 0 {
		return nil, nil, fmt.Errorf("x must satisfy 0 < x < 1")
	}

	// Generate a random 128‑bit positive integer a
	a, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	if a.Sign() == 0 {
		a.Add(a, big.NewInt(1))
	}
	// h = (a * x) mod 1
	h := mulIntFloatMod1(a, x, precBits)

	// Compute integer representations for exact arithmetic
	xInt, err := intFromFloat(x, precBits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert x to integer: %v", err)
	}
	hInt, err := intFromFloat(h, precBits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert h to integer: %v", err)
	}

	pk := &PublicKey{XInt: xInt, HInt: hInt, Prec: precBits}
	sk := &PrivateKey{A: a, PK: *pk}
	return sk, pk, nil
}

// Ciphertext (C1, C2).  Both components stored as integers for exact arithmetic.
type Ciphertext struct {
	c1Int *big.Int // C1: r·xInt mod 2^Prec (exact integer)
	c2Int *big.Int // C2: masked message as integer
	n     int      // number of decimal digits for C2 modulus (10^n)
}

// GetC1Int returns the internal integer representation of C1.
func (ct *Ciphertext) GetC1Int() *big.Int {
	if ct.c1Int == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(ct.c1Int)
}

// GetC2Int returns the internal integer representation of C2.
func (ct *Ciphertext) GetC2Int() *big.Int {
	if ct.c2Int == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(ct.c2Int)
}

// C2 returns the C2 component as a zero-padded decimal string for compatibility.
func (ct *Ciphertext) C2() string {
	if ct.c2Int == nil {
		return strings.Repeat("0", ct.n)
	}
	return fmt.Sprintf("%0*d", ct.n, ct.c2Int)
}

// GetDigitCount returns the number of decimal digits in C2.
func (ct *Ciphertext) GetDigitCount() int {
	return ct.n
}

// Encrypt encodes message m (ASCII or UTF‑8 runes within 0‑255) under pk.
// It returns a probabilistic ciphertext and the random r (useful for tests).
func Encrypt(pk *PublicKey, m string) (*Ciphertext, *big.Int, error) {
	// choose fresh random integer r
	r, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	if r.Sign() == 0 {
		r.Add(r, big.NewInt(1))
	}

	// Encrypt deterministically using r
	c, err := EncryptDeterministic(pk, m, r)

	return c, r, err
}

// helper: 10^n  as *big.Int*
func pow10(n int) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
}

// EncryptDeterministic encodes message m using *integer‑exact* arithmetic.
func EncryptDeterministic(pk *PublicKey, m string, r *big.Int) (*Ciphertext, error) {
	prec := pk.Prec
	n := len(asciiToDigits(m)) // 3·len(m)

	twoPow := new(big.Int).Lsh(big.NewInt(1), prec) // 2^prec

	// ---- Use precomputed integer representations for exact arithmetic ----
	// No float conversions needed - use stored integer values directly

	// ---- C1 = r·x  mod 1 -----------------------------------------------
	c1Int := new(big.Int).Mul(r, pk.XInt)
	c1Int.Mod(c1Int, twoPow)

	// ---- R  = r·h  mod 1 -----------------------------------------------
	Rint := new(big.Int).Mul(r, pk.HInt)
	Rint.Mod(Rint, twoPow)

	// first n decimal digits  Rn = ⌊ R * 10^n ⌋
	Rn := new(big.Int).Mul(Rint, pow10(n))
	Rn.Div(Rn, twoPow) // exact floor

	// ---- mask the message ----------------------------------------------
	Mint, _ := new(big.Int).SetString(asciiToDigits(m), 10)
	c2Int := new(big.Int).Add(Mint, Rn)
	c2Int.Mod(c2Int, pow10(n))

	return &Ciphertext{c1Int: c1Int, c2Int: c2Int, n: n}, nil
}

// Decrypt recovers the plaintext using the same fixed‑point path.
func Decrypt(sk *PrivateKey, ct *Ciphertext) (string, error) {
	prec := sk.PK.Prec
	n := ct.n
	twoPow := new(big.Int).Lsh(big.NewInt(1), prec)

	// R' = a·C1  mod 1   (fixed‑point) - use internal integer directly
	Rint := new(big.Int).Mul(sk.A, ct.c1Int)
	Rint.Mod(Rint, twoPow)

	Rn := new(big.Int).Mul(Rint, pow10(n))
	Rn.Div(Rn, twoPow)

	// Use C2 integer directly - no string conversion needed
	Mint := new(big.Int).Sub(ct.c2Int, Rn)
	if Mint.Sign() < 0 {
		Mint.Add(Mint, pow10(n))
	}
	msgDigits := fmt.Sprintf("%0*d", n, Mint)
	return digitsToASCII(msgDigits)
}

// mulIntFloatMod1 returns (a * x) mod 1 with given precision.
func mulIntFloatMod1(a *big.Int, x *big.Float, prec uint) *big.Float {
	ax := new(big.Float).SetPrec(prec).Mul(new(big.Float).SetPrec(prec).SetInt(a), x)
	return Mod1(ax, prec)
}

// mod1 takes the fractional part (positive inputs only).
func Mod1(f *big.Float, prec uint) *big.Float {
	intPart, _ := f.Int(nil) // floor
	return new(big.Float).SetPrec(prec).Sub(f, new(big.Float).SetInt(intPart))
}

// asciiToDigits encodes text as concatenated 3‑digit ASCII codes.
func asciiToDigits(s string) string {
	var sb strings.Builder
	for _, r := range []byte(s) {
		sb.WriteString(fmt.Sprintf("%03d", r))
	}
	return sb.String()
}

// digitsToASCII decodes a decimal string back to text (3‑digit groups).
func digitsToASCII(d string) (string, error) {
	if len(d)%3 != 0 {
		return "", fmt.Errorf("digits length must be multiple of 3")
	}
	var out strings.Builder
	for i := 0; i < len(d); i += 3 {
		chunk := d[i : i+3]
		val := new(big.Int)
		val, ok := val.SetString(chunk, 10)
		if !ok {
			return "", fmt.Errorf("invalid digit chunk %q", chunk)
		}
		out.WriteByte(byte(val.Int64()))
	}
	return out.String(), nil
}
