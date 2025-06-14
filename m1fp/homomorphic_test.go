package m1fp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"

	"testing"
	"time"
)

// INT returns a *big.Int* from a decimal string (panic on error – debug use).
func INT(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad int: " + s)
	}
	return i
}

func TestHomomorphicAdditionDebug(t *testing.T) {
	// Use the new KeyGen function to create proper keys with common domain
	sk, pk, err := KeyGen(256, X)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// --- two tiny votes ---------------------------------------------------
	msg1, msg2 := "\x01", "\x3F" // 1 and 63

	r1 := big.NewInt(1234567)
	r2 := big.NewInt(7654321)

	ct1, err := EncryptDeterministic(pk, msg1, r1)
	if err != nil {
		t.Fatalf("EncryptDeterministic failed: %v", err)
	}
	ct2, err := EncryptDeterministic(pk, msg2, r2)
	if err != nil {
		t.Fatalf("EncryptDeterministic failed: %v", err)
	}

	//----------------------------------------------------------------------
	//  Ciphertext addition (our library)
	//----------------------------------------------------------------------
	ctSum, err := ct1.Add(ct2, pk.Prec)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	sumPlain, err := Decrypt(sk, ctSum)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	//----------------------------------------------------------------------
	//  PRINT EVERYTHING
	//----------------------------------------------------------------------
	fmt.Println("\n======== COMMON DOMAIN TEST ==========")
	fmt.Printf("Common denominator D      : %s\n", pk.D)
	fmt.Printf("Precision P               : %d\n", pk.Prec)
	fmt.Printf("Decimal digits N          : %d\n", pk.N)
	fmt.Printf("-------------- Cipher 1 --------------\n")
	fmt.Printf("r1                        : %s\n", r1)
	fmt.Printf("C1_1                      : %s\n", ct1.GetC1Int())
	fmt.Printf("C2_1                      : %s\n", ct1.GetC2Int())
	fmt.Printf("M1 (ASCII)                : %s\n", asciiToDigits(msg1))

	fmt.Printf("-------------- Cipher 2 --------------\n")
	fmt.Printf("r2                        : %s\n", r2)
	fmt.Printf("C1_2                      : %s\n", ct2.GetC1Int())
	fmt.Printf("C2_2                      : %s\n", ct2.GetC2Int())
	fmt.Printf("M2 (ASCII)                : %s\n", asciiToDigits(msg2))

	fmt.Printf("-------------- Sum -------------------\n")
	fmt.Printf("C1_sum                    : %s\n", ctSum.GetC1Int())
	fmt.Printf("C2_sum                    : %s\n", ctSum.GetC2Int())
	fmt.Printf("Decrypted sum (library)   : %d %q\n", sumPlain[0], sumPlain)
	fmt.Println("======================================")

	if sumPlain != "\x40" {
		t.Fatalf("homomorphic sum wrong: got %q, expected 64 ('@')", sumPlain)
	}
}

func TestHomomorphicMultipleAdditions(t *testing.T) {
	// Use the new KeyGen function to create proper keys with common domain
	sk, pk, err := KeyGen(256, X)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// Generate random numbers between 0 and 64
	numValues := 5
	values := make([]int, numValues)
	ciphertexts := make([]*Ciphertext, numValues)
	expectedSum := 0

	t.Logf("Testing homomorphic addition of %d random values between 0 and 64", numValues)

	// Generate random values and encrypt them
	for i := 0; i < numValues; i++ {
		// Generate random number between 0 and 64
		randBig, err := rand.Int(rand.Reader, big.NewInt(65)) // 0 to 64 inclusive
		if err != nil {
			t.Fatalf("Failed to generate random number: %v", err)
		}
		values[i] = int(randBig.Int64())
		expectedSum += values[i]

		// Convert to byte representation for encryption (same as debug test)
		msg := string([]byte{byte(values[i])})

		// Use deterministic encryption with a unique random value for each
		r := big.NewInt(int64(1000000 + i*100000)) // Deterministic but unique per value
		ct, err := EncryptDeterministic(pk, msg, r)
		if err != nil {
			t.Fatalf("Encryption failed for value %d: %v", values[i], err)
		}
		ciphertexts[i] = ct

		t.Logf("Value %d: %d (encrypted)", i+1, values[i])
	}

	t.Logf("Expected sum: %d", expectedSum)

	// Handle potential overflow by taking modulo 256
	expectedSumMod := expectedSum % 256
	t.Logf("Expected sum (mod 256): %d", expectedSumMod)

	// Perform homomorphic addition of all ciphertexts
	sumCiphertext, err := AddMany(pk.Prec, ciphertexts...)
	if err != nil {
		t.Fatalf("AddMany failed: %v", err)
	}

	// Decrypt the result
	decryptedSum, err := Decrypt(sk, sumCiphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Convert decrypted result back to integer
	if len(decryptedSum) != 1 {
		t.Fatalf("Expected single byte result, got %d bytes", len(decryptedSum))
	}
	actualSum := int(decryptedSum[0])

	t.Logf("Decrypted sum: %d", actualSum)

	// Verify the result (accounting for modulo 256 arithmetic)
	if actualSum != expectedSumMod {
		t.Fatalf("Homomorphic addition failed: expected %d (mod 256), got %d", expectedSumMod, actualSum)
	}

	t.Logf("✓ Homomorphic addition of %d random values successful!", numValues)
	t.Logf("  Values: %v", values)
	t.Logf("  Raw sum: %d, Modulo 256: %d, Decrypted: %d", expectedSum, expectedSumMod, actualSum)
}

func TestHomomorphicVoting(t *testing.T) {
	const (
		nVotes    = 1000
		maxChoice = 64
	)

	// -------- key pair ----------------------------------------------------
	sk, pk, err := KeyGen(256, X)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	// -------- simulate ballots -------------------------------------------
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	var expected uint64
	var tally *Ciphertext

	for i := 0; i < nVotes; i++ {
		vote := uint64(rng.Intn(maxChoice + 1))
		expected += vote

		ct, _, err := EncryptVote(pk, vote, big.NewInt(int64(i+1))) // cheap deterministic r
		if err != nil {
			t.Fatalf("EncryptVote: %v", err)
		}
		if tally == nil {
			tally = ct
		} else {
			tally, err = tally.Add(ct, pk.Prec)
			if err != nil {
				t.Fatalf("Add: %v", err)
			}
		}
	}

	// -------- decrypt aggregate ------------------------------------------
	got, err := DecryptVote(sk, tally)
	if err != nil {
		t.Fatalf("DecryptVote: %v", err)
	}

	if got != expected {
		t.Fatalf("tally mismatch: got %d, want %d", got, expected)
	}
}

func TestHomomorphicVoting100k(t *testing.T) {
	const (
		nVotes    = 100_000
		maxChoice = 64
	)

	// -------- key pair ----------------------------------------------------
	sk, pk, err := KeyGen(256, X)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	// -------- simulate ballots with fixed seed for reproducibility -------
	rng := mrand.New(mrand.NewSource(12345)) // Fixed seed to reproduce the issue
	var expected uint64
	var tally *Ciphertext

	t.Logf("Testing %d votes with fixed seed for reproducibility", nVotes)

	for i := 0; i < nVotes; i++ {
		vote := uint64(rng.Intn(maxChoice + 1))
		expected += vote

		ct, _, err := EncryptVote(pk, vote, big.NewInt(int64(i+1))) // cheap deterministic r
		if err != nil {
			t.Fatalf("EncryptVote: %v", err)
		}
		if tally == nil {
			tally = ct
		} else {
			tally, err = tally.Add(ct, pk.Prec)
			if err != nil {
				t.Fatalf("Add: %v", err)
			}
		}

		// Log progress every 10k votes
		if (i+1)%10000 == 0 {
			t.Logf("Processed %d votes, expected sum so far: %d", i+1, expected)
		}
	}

	// -------- decrypt aggregate ------------------------------------------
	got, err := DecryptVote(sk, tally)
	if err != nil {
		t.Fatalf("DecryptVote: %v", err)
	}

	t.Logf("Final tally: got %d, expected %d, difference: %d", got, expected, int64(got)-int64(expected))

	if got != expected {
		t.Fatalf("tally mismatch: got %d, want %d (difference: %d)", got, expected, int64(got)-int64(expected))
	}
}
