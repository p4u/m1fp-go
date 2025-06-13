package main

import (
	"fmt"
	"math/big"

	m1fp "github.com/p4u/m1fp-go/m1fp"
)

func main() {
	// Paper parameters -------------------------------------------------------
	prec := uint(256)
	xStr := "0.60943791243410037460075933322619" // ln(5) mod 1, per paper
	aStr := "5940941723"                         // Alice’s chosen secret key
	rStr := "8710936522"                         // Bob’s chosen random r
	msg := "I'm Bob"                             // plaintext

	x, _ := new(big.Float).SetPrec(prec).SetString(xStr)
	a, _ := new(big.Int).SetString(aStr, 10)
	h := new(big.Float).SetPrec(prec)
	h = h.Mul(new(big.Float).SetInt(a), x)
	h = m1fp.Mod1(h, prec)

	pk := &m1fp.PublicKey{X: x, H: h, Prec: prec}
	sk := &m1fp.PrivateKey{A: a, PK: *pk}

	pkbin, err := pk.MarshalBinary()
	if err != nil {
		fmt.Printf("Error marshalling public key: %v\n", err)
		return
	}
	fmt.Printf("Public key (binary): %x\n", pkbin)

	r, _ := new(big.Int).SetString(rStr, 10)
	ct, err := m1fp.EncryptDeterministic(pk, msg, r)
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}
	fmt.Printf("C1 = %0.29f\nC2 = %s\n\n", ct.C1, ct.C2)

	plain, _ := m1fp.Decrypt(sk, ct)
	fmt.Printf("Recovered plaintext: %q\n", plain)
}
