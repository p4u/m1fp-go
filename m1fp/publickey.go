package m1fp

import (
	"encoding/binary"
	"errors"
	"math/big"
)

// PublicKey stores the public parameters as fixed-point integers for exact arithmetic.
type PublicKey struct {
	XInt *big.Int // X as fixed-point integer: ⌊X · 2^Prec⌋
	HInt *big.Int // H as fixed-point integer: ⌊H · 2^Prec⌋
	Prec uint     // working precision in bits
}

// MarshalBinary encodes the public key into a fixed‑length binary blob.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	if pk == nil || pk.XInt == nil || pk.HInt == nil {
		return nil, errors.New("nil receiver or fields")
	}
	if pk.Prec == 0 || pk.Prec > 1<<16-1 {
		return nil, errors.New("unsupported precision")
	}

	k := int((pk.Prec + 7) / 8) // bytes per coordinate
	buf := make([]byte, 2+2*k)

	// 1) precision
	binary.BigEndian.PutUint16(buf[:2], uint16(pk.Prec))

	// 2) X - use integer representation
	pk.XInt.FillBytes(buf[2 : 2+k]) // left‑pad to k bytes

	// 3) H - use integer representation
	pk.HInt.FillBytes(buf[2+k:]) // left‑pad to k bytes

	return buf, nil
}

// UnmarshalBinary decodes the binary blob back into a PublicKey.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("truncated input")
	}
	prec := binary.BigEndian.Uint16(data[:2])
	k := int((uint(prec) + 7) / 8)
	if len(data) != 2+2*k {
		return errors.New("invalid length for given precision")
	}

	xBytes := data[2 : 2+k]
	hBytes := data[2+k:]

	pk.Prec = uint(prec)
	pk.XInt = new(big.Int).SetBytes(xBytes)
	pk.HInt = new(big.Int).SetBytes(hBytes)
	return nil
}

// intFromFloat returns ⌊f · 2^prec⌋ as *big.Int*.
func intFromFloat(f *big.Float, prec uint) (*big.Int, error) {
	if f.Sign() < 0 || f.Cmp(big.NewFloat(1).SetPrec(f.Prec())) >= 0 {
		return nil, errors.New("value not in [0,1)")
	}
	twoPow := new(big.Float).SetPrec(prec).SetInt(new(big.Int).Lsh(big.NewInt(1), prec))
	scaled := new(big.Float).SetPrec(prec).Mul(f, twoPow) // exact: f∈[0,1)
	i, _ := scaled.Int(nil)                               // floor
	return i, nil
}
