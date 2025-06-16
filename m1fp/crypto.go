// Package m1fp implements the public-key encryption scheme
// proposed by El-Yahyaoui & Omary (2022). Security rests on the
// Modulo-1 Factoring Problem (M1FP), believed NP-hard and
// resistant to quantum attacks.
//
// All arithmetic uses exact integer operations in a unified common domain
// to eliminate precision errors in homomorphic operations.
package m1fp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// X is the default irrational number used as the public parameter.
// This represents ln(5) mod 1 with high precision.
const X = "0.6094379124341003746007593332261876395256013542685177219126478914741789877076578"

// PrivateKey contains the secret key material for M1FP encryption.
// The secret integer A is never exposed outside this structure.
type PrivateKey struct {
	A  *big.Int  // Secret integer used for decryption
	PK PublicKey // Associated public key
}

// KeyGen generates a new M1FP key pair using the common domain approach.
// The common domain D = 2^P · 5^n eliminates precision errors in homomorphic operations.
//
// Parameters:
//   - precBits: arithmetic precision in bits (minimum 128, recommended 256)
//   - xString: textual representation of an irrational number in (0,1)
//
// Returns the private key, public key, and any error encountered.
func KeyGen(precBits uint16, xString string) (*PrivateKey, *PublicKey, error) {
	if precBits < 128 {
		return nil, nil, fmt.Errorf("precision too small")
	}
	x, ok := new(big.Float).SetPrec(uint(precBits)).SetString(xString)
	if !ok {
		return nil, nil, fmt.Errorf("invalid x string")
	}
	if x.Sign() <= 0 || x.Cmp(big.NewFloat(1).SetPrec(uint(precBits))) >= 0 {
		return nil, nil, fmt.Errorf("x must satisfy 0 < x < 1")
	}

	a, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	if a.Sign() == 0 {
		a.Add(a, big.NewInt(1))
	}

	h := mulIntFloatMod1(a, x, precBits)
	n := uint16(VoteDigits)
	d := computeCommonDenominator(precBits, n)

	xInt, err := liftToCommonDomain(x, d, precBits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lift x to common domain: %v", err)
	}
	hInt, err := liftToCommonDomain(h, d, precBits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lift h to common domain: %v", err)
	}

	pk := &PublicKey{XInt: xInt, HInt: hInt, D: d, Prec: precBits, N: n}
	sk := &PrivateKey{A: a, PK: *pk}
	return sk, pk, nil
}

// Ciphertext represents an encrypted message in the common domain D = 2^P · 5^n.
// Both components are stored as integers for exact arithmetic operations.
type Ciphertext struct {
	c1 *big.Int // First component: (r · X) mod D
	c2 *big.Int // Second component: (M + r · H) mod D
	d  *big.Int // Common denominator D for arithmetic operations
	n  uint     // Number of decimal digits for message encoding
}

// GetC1Int returns the internal integer representation of C1.
func (ct *Ciphertext) GetC1Int() *big.Int {
	if ct.c1 == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(ct.c1)
}

// GetC2Int returns the internal integer representation of C2.
func (ct *Ciphertext) GetC2Int() *big.Int {
	if ct.c2 == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(ct.c2)
}

// C2 returns the C2 component as a zero-padded decimal string for compatibility.
func (ct *Ciphertext) C2() string {
	if ct.c2 == nil {
		return strings.Repeat("0", int(ct.n))
	}
	return fmt.Sprintf("%0*d", int(ct.n), ct.c2)
}

// GetDigitCount returns the number of decimal digits in C2.
func (ct *Ciphertext) GetDigitCount() int {
	return int(ct.n)
}

// Encrypt encodes a message using probabilistic encryption.
// The message m should contain ASCII or UTF-8 characters with byte values 0-255.
// Returns the ciphertext, the random value used (for testing), and any error.
func Encrypt(pk *PublicKey, m string) (*Ciphertext, *big.Int, error) {
	r, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	if r.Sign() == 0 {
		r.Add(r, big.NewInt(1))
	}

	c, err := EncryptDeterministic(pk, m, r)
	return c, r, err
}

// EncryptDeterministic encrypts a message using a specified random value.
// Uses the common domain approach to eliminate precision loss in homomorphic operations.
// The message is encoded as ASCII digits and lifted to the common domain D = 2^P · 5^n.
func EncryptDeterministic(pk *PublicKey, m string, r *big.Int) (*Ciphertext, error) {
	n := len(asciiToDigits(m))
	if pk.Prec < uint16(n) {
		return nil, fmt.Errorf("precision %d too small for %d digits", pk.Prec, n)
	}

	messageInt, _ := new(big.Int).SetString(asciiToDigits(m), 10)
	scaleFactor := new(big.Int).Lsh(big.NewInt(1), uint(pk.Prec)-uint(n))
	M := new(big.Int).Mul(messageInt, scaleFactor)

	c1 := new(big.Int).Mul(r, pk.XInt)
	c1.Mod(c1, pk.D)

	rH := new(big.Int).Mul(r, pk.HInt)
	rH.Mod(rH, pk.D)

	c2 := new(big.Int).Add(M, rH)
	c2.Mod(c2, pk.D)

	return &Ciphertext{c1: c1, c2: c2, d: new(big.Int).Set(pk.D), n: uint(n)}, nil
}

// Decrypt recovers the original message from a ciphertext.
// Uses the common domain approach to maintain precision throughout the decryption process.
// Applies proper rounding when converting back from the scaled representation.
func Decrypt(sk *PrivateKey, ct *Ciphertext) (string, error) {
	if ct.d == nil {
		return "", fmt.Errorf("missing common denominator in ciphertext")
	}

	n := ct.n
	if sk.PK.Prec < uint16(n) {
		return "", fmt.Errorf("precision %d too small for %d digits", sk.PK.Prec, n)
	}

	aC1 := new(big.Int).Mul(sk.A, ct.c1)
	aC1.Mod(aC1, ct.d)

	MPrime := new(big.Int).Sub(ct.c2, aC1)
	if MPrime.Sign() < 0 {
		MPrime.Add(MPrime, ct.d)
	}

	scaleFactor := new(big.Int).Lsh(big.NewInt(1), uint(sk.PK.Prec)-n)
	messageInt := new(big.Int)
	remainder := new(big.Int)
	messageInt.DivMod(MPrime, scaleFactor, remainder)

	if remainder.Sign() != 0 {
		halfScale := new(big.Int).Div(scaleFactor, big.NewInt(2))
		if remainder.Cmp(halfScale) >= 0 {
			messageInt.Add(messageInt, big.NewInt(1))
		}
	}

	msgDigits := fmt.Sprintf("%0*d", int(n), messageInt)
	return digitsToASCII(msgDigits)
}

// mulIntFloatMod1 computes (a * x) mod 1 with the specified precision.
// Used internally for key generation to compute h = (a * x) mod 1.
func mulIntFloatMod1(a *big.Int, x *big.Float, prec uint16) *big.Float {
	ax := new(big.Float).SetPrec(uint(prec)).Mul(new(big.Float).SetPrec(uint(prec)).SetInt(a), x)
	return Mod1(ax, prec)
}

// Mod1 returns the fractional part of a floating-point number.
// Equivalent to f - floor(f) for positive inputs.
func Mod1(f *big.Float, prec uint16) *big.Float {
	intPart, _ := f.Int(nil)
	return new(big.Float).SetPrec(uint(prec)).Sub(f, new(big.Float).SetInt(intPart))
}

// asciiToDigits encodes text as concatenated 3-digit ASCII codes.
// Each byte is converted to a 3-digit decimal representation (e.g., 'A' -> "065").
func asciiToDigits(s string) string {
	var sb strings.Builder
	for _, r := range []byte(s) {
		sb.WriteString(fmt.Sprintf("%03d", r))
	}
	return sb.String()
}

// digitsToASCII decodes a decimal string back to text using 3-digit groups.
// Each group of 3 digits is converted back to its corresponding ASCII character.
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
