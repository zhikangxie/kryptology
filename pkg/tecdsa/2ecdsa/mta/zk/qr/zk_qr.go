package zk_qr

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk"
	"github.com/gtank/merlin"
)

type Param struct {
	N0 *big.Int
}

type Commitment struct {
	a [zk.T]*big.Int
}

type Proof struct {
	z [zk.T]*big.Int
	e *big.Int
}

type Statement struct {
	h *big.Int
}

type Witness struct {
	h_sqrt *big.Int
}

type Prover struct {
	pp *Param
	tx *merlin.Transcript
}

type Verifier struct {
	pp *Param
	tx *merlin.Transcript
}

func (prover *Prover) Prove(witness Witness) (Statement, Proof) {
	h := new(big.Int).Mod(new(big.Int).Mul(witness.h_sqrt, witness.h_sqrt), prover.pp.N0)
	prover.tx.AppendMessage([]byte("h"), h.Bytes())

	// Step 1: Commit
	r := [zk.T]*big.Int{}
	a := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		r[i], _ = rand.Int(rand.Reader, prover.pp.N0)
		a[i] = new(big.Int).Mod(new(big.Int).Mul(r[i], r[i]), prover.pp.N0) // a = r^2 % N0
		prover.tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a[i].Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(prover.tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 3: Prove
	z := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		// z = h_sqrt^e * r % N0
		if e.Bit(i) == 0 {
			z[i] = r[i]
		} else {
			z[i] = new(big.Int).Mod(new(big.Int).Mul(r[i], witness.h_sqrt), prover.pp.N0)
		}
	}

	return Statement{h}, Proof{z, e}
}

func (verifier *Verifier) Verify(statement Statement, commitment Commitment, proof Proof) bool {
	verifier.tx.AppendMessage([]byte("h"), statement.h.Bytes())

	for i := 0; i < zk.T; i++ {
		verifier.tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), commitment.a[i].Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(verifier.tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 4: Verify
	for i := 0; i < zk.T; i++ {
		z2 := new(big.Int).Mod(new(big.Int).Mul(proof.z[i], proof.z[i]), verifier.pp.N0)
		// z^2 = h^e * a % N0
		if e.Bit(i) == 0 {
			if z2.Cmp(commitment.a[i]) != 0 {
				return false
			}
		} else {
			if z2.Cmp(new(big.Int).Mod(new(big.Int).Mul(commitment.a[i], statement.h), verifier.pp.N0)) != 0 {
				return false
			}
		}
	}
	return true
}

func (verifier *Verifier) VerifyWithoutCom(statement Statement, proof Proof) bool {
	verifier.tx.AppendMessage([]byte("h"), statement.h.Bytes())
	var a *big.Int

	for i := 0; i < zk.T; i++ {
		z2 := new(big.Int).Mod(new(big.Int).Mul(proof.z[i], proof.z[i]), verifier.pp.N0)
		// a = h^-e * z^2 % N0
		if proof.e.Bit(i) == 0 {
			a = z2
		} else {
			a = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).ModInverse(statement.h, verifier.pp.N0), z2), verifier.pp.N0)
		}

		verifier.tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a.Bytes())
	}

	e := new(big.Int).SetBytes(verifier.tx.ExtractBytes([]byte("e"), zk.T/8))

	if e.Cmp(proof.e) != 0 {
		return false
	}

	return true
}
