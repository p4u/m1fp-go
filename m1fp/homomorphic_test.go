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
	prec := uint(256)
	xStr := "0.60943791243410037460075933322619"
	aStr := "5940941723"

	// --- key material -----------------------------------------------------
	x, _ := new(big.Float).SetPrec(prec).SetString(xStr)
	a, _ := new(big.Int).SetString(aStr, 10)
	h := Mod1(new(big.Float).SetPrec(prec).Mul(new(big.Float).SetInt(a), x), prec)

	pk := &PublicKey{X: x, H: h, Prec: prec}
	sk := &PrivateKey{A: a, PK: *pk}

	// --- two tiny votes ---------------------------------------------------
	msg1, msg2 := "\x01", "\x3F" // 1 and 63

	r1 := big.NewInt(1234567)
	r2 := big.NewInt(7654321)

	ct1, _ := EncryptDeterministic(pk, msg1, r1)
	ct2, _ := EncryptDeterministic(pk, msg2, r2)

	//----------------------------------------------------------------------
	//  Hand‑compute every intermediate number for ciphertext‑1
	//----------------------------------------------------------------------
	n := len(ct1.C2)
	pow10n := pow10(n)
	twoPow := new(big.Int).Lsh(big.NewInt(1), prec)

	xInt, _ := intFromFloat(pk.X, prec)
	hInt, _ := intFromFloat(pk.H, prec)

	c1Int1 := new(big.Int).Mul(r1, xInt)
	c1Int1.Mod(c1Int1, twoPow)

	Rint1 := new(big.Int).Mul(r1, hInt)
	Rint1.Mod(Rint1, twoPow)
	Rn1 := new(big.Int).Mul(Rint1, pow10n)
	Rn1.Div(Rn1, twoPow)

	//----------------------------------------------------------------------
	//  Same for ciphertext‑2
	//----------------------------------------------------------------------
	c1Int2 := new(big.Int).Mul(r2, xInt)
	c1Int2.Mod(c1Int2, twoPow)

	Rint2 := new(big.Int).Mul(r2, hInt)
	Rint2.Mod(Rint2, twoPow)
	Rn2 := new(big.Int).Mul(Rint2, pow10n)
	Rn2.Div(Rn2, twoPow)

	//----------------------------------------------------------------------
	//  Ciphertext addition (our library)
	//----------------------------------------------------------------------
	ctSum, _ := ct1.Add(ct2, prec)
	sumPlain, _ := Decrypt(sk, ctSum)

	//----------------------------------------------------------------------
	//  Independent recomputation for the SUM
	//----------------------------------------------------------------------
	// fractional part
	c1IntSum := new(big.Int).Add(c1Int1, c1Int2)
	c1IntSum.Mod(c1IntSum, twoPow)

	// shared secret
	RintSum := new(big.Int).Mul(sk.A, c1IntSum)
	RintSum.Mod(RintSum, twoPow)
	RnSum := new(big.Int).Mul(RintSum, pow10n)
	RnSum.Div(RnSum, twoPow)

	C2_1_int := INT(ct1.C2)
	C2_2_int := INT(ct2.C2)

	//----------------------------------------------------------------------
	//  PRINT EVERYTHING
	//----------------------------------------------------------------------
	fmt.Println("\n======== FULL TRACE ==========")
	fmt.Printf("n (digits)                : %d\n", n)
	fmt.Printf("10^n                      : %s\n", pow10n)
	fmt.Printf("-------------- Cipher 1 --------------\n")
	fmt.Printf("r1                        : %s\n", r1)
	fmt.Printf("C1_1 int                  : %s\n", c1Int1)
	fmt.Printf("Rint1                     : %s\n", Rint1)
	fmt.Printf("Rn1                       : %s\n", Rn1)
	fmt.Printf("M1                        : %s (digits %s)\n", asciiToDigits(msg1), asciiToDigits(msg1))
	fmt.Printf("C2_1                      : %s\n", ct1.C2)

	fmt.Printf("-------------- Cipher 2 --------------\n")
	fmt.Printf("r2                        : %s\n", r2)
	fmt.Printf("C1_2 int                  : %s\n", c1Int2)
	fmt.Printf("Rint2                     : %s\n", Rint2)
	fmt.Printf("Rn2                       : %s\n", Rn2)
	fmt.Printf("M2                        : %s (digits %s)\n", asciiToDigits(msg2), asciiToDigits(msg2))
	fmt.Printf("C2_2                      : %s\n", ct2.C2)

	fmt.Printf("-------------- Sum -------------------\n")
	fmt.Printf("C1_sum int (calc)         : %s\n", c1IntSum)
	fmt.Printf("RintSum                   : %s\n", RintSum)
	fmt.Printf("RnSum                     : %s\n", RnSum)
	fmt.Printf("C2_sum (lib)              : %s\n", ctSum.C2)
	fmt.Printf("C2_sum int (indep)        : (C2_1+C2_2) mod 10^n = %s\n", new(big.Int).Mod(new(big.Int).Add(C2_1_int, C2_2_int), pow10n))
	fmt.Printf("Decrypted sum (library)   : %d %q\n", sumPlain[0], sumPlain)
	fmt.Println("======================================")

	if sumPlain != "\x40" {
		t.Fatalf("homomorphic sum wrong: got %q, expected 64 ('@')", sumPlain)
	}
}

func TestHomomorphicMultipleAdditions(t *testing.T) {
	// Use the same key material as the working debug test
	prec := uint(256)
	xStr := "0.60943791243410037460075933322619"
	aStr := "5940941723"

	// --- key material (same as debug test) -------------------------------
	x, _ := new(big.Float).SetPrec(prec).SetString(xStr)
	a, _ := new(big.Int).SetString(aStr, 10)
	h := Mod1(new(big.Float).SetPrec(prec).Mul(new(big.Float).SetInt(a), x), prec)

	pk := &PublicKey{X: x, H: h, Prec: prec}
	sk := &PrivateKey{A: a, PK: *pk}

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
	sumCiphertext, err := AddMany(prec, ciphertexts...)
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
		nVotes    = 100_00
		maxChoice = 64
	)

	// -------- key pair ----------------------------------------------------
	xStr := "0.60943791243410037460075933322619"
	sk, pk, err := KeyGen(256, xStr)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	// -------- simulate ballots -------------------------------------------
	mrand.Seed(time.Now().UnixNano())
	var expected uint64
	var tally *Ciphertext

	for i := 0; i < nVotes; i++ {
		vote := uint64(mrand.Intn(maxChoice + 1))
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
