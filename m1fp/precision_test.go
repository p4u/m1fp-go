package m1fp

import (
	"math/big"
	"testing"
)

// TestIntegerArithmeticPrecision tests that our integer-based arithmetic
// is exact and doesn't accumulate rounding errors.
func TestIntegerArithmeticPrecision(t *testing.T) {
	// Test with the same key material as the main tests
	xStr := "0.60943791243410037460075933322619"
	sk, pk, err := KeyGen(256, xStr)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	// Verify that XInt and HInt are properly set
	if pk.XInt == nil {
		t.Fatal("pk.XInt is nil")
	}
	if pk.HInt == nil {
		t.Fatal("pk.HInt is nil")
	}

	// Test that encryption uses integer arithmetic
	vote := uint64(42)
	r := big.NewInt(12345)

	ct, _, err := EncryptVote(pk, vote, r)
	if err != nil {
		t.Fatalf("EncryptVote: %v", err)
	}

	// Verify that c1Int is set
	if ct.c1Int == nil {
		t.Fatal("ct.c1Int is nil")
	}

	// Test decryption
	decrypted, err := DecryptVote(sk, ct)
	if err != nil {
		t.Fatalf("DecryptVote: %v", err)
	}

	if decrypted != vote {
		t.Fatalf("Decryption failed: got %d, want %d", decrypted, vote)
	}

	// Test that multiple encryptions with the same parameters produce identical results
	ct2, _, err := EncryptVote(pk, vote, r)
	if err != nil {
		t.Fatalf("EncryptVote (second): %v", err)
	}

	if ct.c1Int.Cmp(ct2.c1Int) != 0 {
		t.Fatal("Deterministic encryption produced different c1Int values")
	}

	if ct.C2() != ct2.C2() {
		t.Fatal("Deterministic encryption produced different C2 values")
	}
}

// TestHomomorphicAdditionPrecision tests that homomorphic addition
// maintains precision over multiple operations.
func TestHomomorphicAdditionPrecision(t *testing.T) {
	xStr := "0.60943791243410037460075933322619"
	sk, pk, err := KeyGen(256, xStr)
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	// Test with a moderate number of additions (1000)
	const numVotes = 1000
	var expectedSum uint64
	var tally *Ciphertext

	for i := 0; i < numVotes; i++ {
		vote := uint64(i % 65) // 0 to 64
		expectedSum += vote

		ct, _, err := EncryptVote(pk, vote, big.NewInt(int64(i+1)))
		if err != nil {
			t.Fatalf("EncryptVote at %d: %v", i, err)
		}

		if tally == nil {
			tally = ct
		} else {
			tally, err = tally.Add(ct, pk.Prec)
			if err != nil {
				t.Fatalf("Add at %d: %v", i, err)
			}
		}
	}

	// Decrypt and verify
	got, err := DecryptVote(sk, tally)
	if err != nil {
		t.Fatalf("DecryptVote: %v", err)
	}

	if got != expectedSum {
		t.Fatalf("Precision test failed: got %d, want %d (difference: %d)",
			got, expectedSum, int64(got)-int64(expectedSum))
	}

	t.Logf("✓ Precision test passed for %d votes: sum = %d", numVotes, expectedSum)
}
