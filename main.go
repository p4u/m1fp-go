// Package main demonstrates the M1FP homomorphic encryption system
// with perfect precision using the common domain approach.
package main

import (
	"fmt"
	"math/big"

	m1fp "github.com/p4u/m1fp-go/m1fp"
)

func main() {
	// Generate M1FP key pair using high-precision ln(5) as the irrational parameter
	sk, pk, err := m1fp.KeyGen(256, m1fp.X)
	if err != nil {
		fmt.Printf("KeyGen error: %v\n", err)
		return
	}

	// Encrypt two votes using deterministic randomness for reproducible results
	ct1, _, err := m1fp.EncryptVote(pk, 1, big.NewInt(1234567))
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}

	ct2, _, err := m1fp.EncryptVote(pk, 63, big.NewInt(7654321))
	if err != nil {
		fmt.Printf("Encryption error: %v\n", err)
		return
	}

	// Perform homomorphic addition in the common domain
	sum, err := ct1.Add(ct2, pk.Prec)
	if err != nil {
		fmt.Printf("Addition error: %v\n", err)
		return
	}

	// Decrypt the final tally with perfect precision
	tally, err := m1fp.DecryptVote(sk, sum)
	if err != nil {
		fmt.Printf("Decryption error: %v\n", err)
		return
	}

	fmt.Printf("Vote 1: 1\n")
	fmt.Printf("Vote 2: 63\n")
	fmt.Printf("Homomorphic tally: %d\n", tally) // Should be 64

	// Demonstrate binary key serialization
	pkbin, err := pk.MarshalBinary()
	if err != nil {
		fmt.Printf("Error marshalling public key: %v\n", err)
		return
	}
	fmt.Printf("Public key size: %d bytes => %x\n", len(pkbin), pkbin)

	// Verify key deserialization
	var pk2 m1fp.PublicKey
	err = pk2.UnmarshalBinary(pkbin)
	if err != nil {
		fmt.Printf("Error unmarshalling public key: %v\n", err)
		return
	}
}
