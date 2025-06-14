package m1fp

import (
	"encoding/binary"
	"errors"
	"math/big"
)

// PublicKey stores the public parameters in the common domain D = 2^P · 5^n.
// This unified representation eliminates precision errors in homomorphic operations.
type PublicKey struct {
	XInt *big.Int // X lifted to common domain: ⌊X · D⌋
	HInt *big.Int // H lifted to common domain: ⌊H · D⌋
	D    *big.Int // Common denominator: 2^P · 5^n
	Prec uint     // P: binary precision in bits
	N    uint     // n: decimal precision (digits)
}

// MarshalBinary encodes the public key into a compact binary representation.
// The format includes precision, decimal digits, and the variable-length X and H components.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	if pk == nil || pk.XInt == nil || pk.HInt == nil {
		return nil, errors.New("nil receiver or fields")
	}
	if pk.Prec == 0 || pk.Prec > 1<<16-1 {
		return nil, errors.New("unsupported precision")
	}

	xBytes := pk.XInt.Bytes()
	hBytes := pk.HInt.Bytes()

	// Format: [prec:2][n:2][xLen:4][hLen:4][xBytes][hBytes]
	buf := make([]byte, 12+len(xBytes)+len(hBytes))

	binary.BigEndian.PutUint16(buf[0:2], uint16(pk.Prec))
	binary.BigEndian.PutUint16(buf[2:4], uint16(pk.N))
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(xBytes)))
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(hBytes)))

	copy(buf[12:12+len(xBytes)], xBytes)
	copy(buf[12+len(xBytes):], hBytes)

	return buf, nil
}

// UnmarshalBinary decodes a binary representation back into a PublicKey.
// The common denominator D is recomputed from the precision and decimal digits.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return errors.New("truncated input")
	}

	prec := binary.BigEndian.Uint16(data[0:2])
	n := binary.BigEndian.Uint16(data[2:4])
	xLen := binary.BigEndian.Uint32(data[4:8])
	hLen := binary.BigEndian.Uint32(data[8:12])

	if len(data) != int(12+xLen+hLen) {
		return errors.New("invalid length")
	}

	xBytes := data[12 : 12+xLen]
	hBytes := data[12+xLen : 12+xLen+hLen]

	pk.Prec = uint(prec)
	pk.N = uint(n)
	pk.XInt = new(big.Int).SetBytes(xBytes)
	pk.HInt = new(big.Int).SetBytes(hBytes)
	pk.D = computeCommonDenominator(pk.Prec, pk.N)

	return nil
}

// computeCommonDenominator calculates D = 2^P · 5^n for the unified arithmetic domain.
// This denominator ensures exact conversions between binary and decimal representations.
func computeCommonDenominator(p, n uint) *big.Int {
	twoPowP := new(big.Int).Lsh(big.NewInt(1), p)
	fivePowN := new(big.Int).Exp(big.NewInt(5), big.NewInt(int64(n)), nil)
	return new(big.Int).Mul(twoPowP, fivePowN)
}

// liftToCommonDomain converts a fractional value f ∈ [0,1) to the common domain
// by computing ⌊f · D⌋ where D is the common denominator.
// This operation preserves precision by avoiding intermediate rounding.
func liftToCommonDomain(f *big.Float, d *big.Int, prec uint) (*big.Int, error) {
	if f.Sign() < 0 || f.Cmp(big.NewFloat(1).SetPrec(f.Prec())) >= 0 {
		return nil, errors.New("value not in [0,1)")
	}

	dFloat := new(big.Float).SetPrec(prec).SetInt(d)
	scaled := new(big.Float).SetPrec(prec).Mul(f, dFloat)
	result, _ := scaled.Int(nil)
	return result, nil
}
