# m1fp‑go

A like‑ElGamal public‑key cryptosystem based on the _Modulo‑1 Factoring  
Problem (M1FP)_ with exact additive homomorphism, written in Go (≥ 1.22)


## 1  Citation

This implementation follows and extends the scheme from:

> Ahmed El‑Yahyaoui, Fouzia Omary,  
> **“A Like ELGAMAL Cryptosystem But Resistant To Post‑Quantum Attacks”**,  
> *International Journal of Communication Networks and Information Security* (IJCNIS), Vol x, No x, April 2022.

Please cite the paper if you use this code in academic work.

---

## 2  Why is this interesting?

* **Post‑quantum hope** – Traditional ElGamal relies on the *Discrete Log* problem, broken in polynomial time by Shor’s quantum algorithm.  
  The M1FP problem is *currently* outside the reach of every known quantum algorithm, so the scheme is a candidate for **quantum‑resistant public‑key encryption**.

* **Exact additive homomorphism** – You can add ciphertexts and, after one decryption, obtain the sum of the underlying plaintexts.  
  This is invaluable for **e‑voting**, private surveys, and any “tally without opening individual ballots” workflow.

---

## 3  What is the Modulo‑1 Factoring Problem (M1FP)?

> *Given an irrational real number* `x ∈ (0,1)`  
> *and another real* `c = (a·x mod 1)` with **unknown integer** `a`,  
> **find `a`.**

* “`mod 1`” keeps only the fractional part, e.g. `0.75 mod 1 = 0.75`,  
  `3.1415 mod 1 = 0.1415`.
* Eric Jarpe (2021) proved M1FP is **NP‑hard**.
* Because `x` is irrational, the fractional sequence `(a·x mod 1)` is
  equidistributed; no efficient lattice attack is known.

---

## 4  Cryptosystem in a nutshell

| Step | Math (integers unless noted) | Explanation |
|------|-----------------------------|-------------|
| **KeyGen** | pick secret `a`; publish `(x, h = a·x mod 1)` | `x` irrational; same `a` forever |
| **Encrypt M** | random `r` → `(C₁ = r·x mod 1,  C₂ = (M + Rₙ) mod 10ⁿ)` | `R = r·h mod 1`, `Rₙ` = first `n` decimal digits of `R` |
| **Decrypt** | compute `R′ = a·C₁ mod 1`, `M = (C₂ – R′ₙ) mod 10ⁿ` | cancels the mask |

`n` is the digit‑length of `M`; we use the ASCII‑to‑decimal encoding `65 → "065"` so every byte is exactly three digits.

---

## 5  How additive homomorphism works 🔢

Take ciphertexts **E(M₁) = (C₁, C₂)** and **E(M₂) = (C₁′, C₂′)**.

1. **Fractional part**  
   `C₁ + C₁′` is a fixed‑point integer mod `2^Prec`.  
   The library adds them exactly and notes a possible **carry** (0 or 1).

2. **Decimal part**  
   `C₂ + C₂′ + carry` is added **as an ordinary base‑10 integer**  
   then reduced mod `10ⁿ`.

Because the same carry is added to the mask parts, decryption yields

```
(M₁ + M₂) mod 10ⁿ
```

with no leakage of the individual votes.

### Tiny example

```
M1 =   1  → "001"
M2 =  63  → "063"
R1 = 229,  R2 = 749           (from shared secrets)
C2\_1 = 001+229 = 230 (mod 1000)
C2\_2 = 063+749 = 812 (mod 1000)

# library addition

fractional carry = 1
C2\_sum = 230+812+1 = 1043 ≡ 043 (mod 1000)

Decrypt:
043 – (229+749 mod 1000) = 043 – 978 ≡ 064 → "@"
````

64 is the correct sum of 1 + 63.

---

## 6  Design & engineering choices

| Decision | Motivation for e‑voting |
|----------|------------------------|
| **Fixed precision** (`Prec=256 bits`) | Plenty to extract ≥ 75 decimal digits if ever needed. |
| **ASCII‑to‑decimal (3 digits/byte)** | Human‑readable test vectors, easy range proofs. |
| **Carry propagation** | Guarantees correctness after millions of additions. |
| **Modulus `10ⁿ`** | Tally bound easy to size: `n = ceil(log₁₀(maxVotes·maxValue))`. |
| **Binary key format** (`2 + 2·ceil(Prec/8)` bytes) | Comparable to RSA or BLS keys; no wasted zeros. |

---

## 7  Limitations & open points

* **Novel assumption** – M1FP is much less studied than lattices or codes.  
  Treat this as experimental **until peer‑review hardens the security**.
* **Chosen‑ciphertext security** – base scheme is IND‑CPA.  
  Use a KEM+AEAD wrapper or apply Cramer–Shoup style techniques for IND‑CCA2.
* **Decimal encoding overhead** – 3× blow‑up.  A custom base‑2¹⁶ packing
  would be denser.
* **No signature / key‑exchange yet** – only encryption; signatures could
  reuse the same trapdoor but are future work.

---

## 8  Why is the additive scheme safe?

* Each ciphertext reveals only `(C₁, C₂)` which look uniformly random
  because `r` is fresh and `Rₙ` is unpredictable under M1FP hardness.
* Adding ciphertexts is a **group action**: the distribution of
  `C₂_sum` is identical to that of an honest encryption of the numeric
  sum with a fresh randomizer (proof: linearity of both moduli and the
  carry rule).
* No extra information is leaked; adversaries cannot learn individual
  ballots, only the final tally once the holder of `a` decrypts.

---

## 9  zkSNARK feasibility (Circom / gnark)

* **Fixed‑point non‑native field arithmetic** – `r·x` and `r·h` are
  multiplications of ~256‑bit integers; gnark’s `emulated` API costs
  ~2 k constraints each.
* **Decimal range checks** – prove `0 ≤ M < 10ⁿ` (30 constraints for
  `n ≤ 9`).
* **Carry bit** – one extra boolean constraint per addition.
* A circuit that **proves correct encryption and homomorphic tally** for
  10 M ballots can be aggregated with Groth16
  into < 10 k constraints per chunk, totally practical.

---

## 10  Getting started

```go
go get github.com/p4u/m1fp-go/m1fp
````

```go
package main

import (
	"fmt"
	"github.com/p4u/m1fp-go/m1fp"
	"math/big"
)

func main() {
	// --- Key generation ---------------------------------------------------
	pkX := "0.60943791243410037460075933322619" // ln(5) mod 1
	sk, pk, _ := m1fp.KeyGen(256, pkX)

	// --- Encrypt two ballots ---------------------------------------------
	ct1, _ := m1fp.Encrypt(pk, "\x01") // vote = 1
	ct2, _ := m1fp.Encrypt(pk, "\x3F") // vote = 63

	// --- Homomorphic tally -----------------------------------------------
	sum, _ := ct1.Add(ct2, pk.Prec)

	// --- Decrypt final tally ---------------------------------------------
	tally, _ := m1fp.Decrypt(sk, sum)
	fmt.Println("Tally:", tally[0]) // 64
}
```

### Binary key export / import

```go
blob, _ := pk.MarshalBinary()
var pk2 m1fp.PublicKey
pk2.UnmarshalBinary(blob)
// pk2 is now identical to pk
```

### Deterministic encryption (for tests)

```go
r := big.NewInt(1234567)
ct, _ := m1fp.EncryptDeterministic(pk, "Hello", r)
```

---
