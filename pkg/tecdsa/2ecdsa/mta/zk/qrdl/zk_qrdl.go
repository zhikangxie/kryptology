package zk_qrdl

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk"
	"github.com/gtank/merlin"
)

type Param struct {
	N0 *big.Int
	h  *big.Int
}

type Commitment struct {
	a [zk.T]*big.Int
}

type Proof struct {
	z [zk.T]*big.Int
	e *big.Int
}

type Statement struct {
	g *big.Int
}

type Witness struct {
	alpha *big.Int
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
	n := new(big.Int).Lsh(prover.pp.N0, zk.S-1)
	g := new(big.Int).Exp(prover.pp.h, witness.alpha, prover.pp.N0)
	prover.tx.AppendMessage([]byte("g"), g.Bytes())

	// Step 1: Commit
	beta := [zk.T]*big.Int{}
	a := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		b, _ := rand.Int(rand.Reader, n)
		beta[i] = new(big.Int).Lsh(b, 1)                            // beta <$- [1, 2^s * N0) and beta is even
		a[i] = new(big.Int).Exp(prover.pp.h, beta[i], prover.pp.N0) // a = h^beta % N0
		prover.tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a[i].Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(prover.tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 3: Prove
	z := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		// z = h_sqrt^e * r % N0
		if e.Bit(i) == 0 {
			z[i] = beta[i]
		} else {
			z[i] = new(big.Int).Add(witness.alpha, beta[i])
		}
	}

	return Statement{g}, Proof{z, e}
}

func (verifier *Verifier) Verify(statement Statement, commitment Commitment, proof Proof) bool {
	verifier.tx.AppendMessage([]byte("g"), statement.g.Bytes())

	for i := 0; i < zk.T; i++ {
		verifier.tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), commitment.a[i].Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(verifier.tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 4: Verify
	for i := 0; i < zk.T; i++ {
		h_to_z := new(big.Int).Exp(verifier.pp.h, proof.z[i], verifier.pp.N0)
		// h^z = g^e * a % N0
		if e.Bit(i) == 0 {
			if h_to_z.Cmp(commitment.a[i]) != 0 {
				return false
			}
		} else {
			if h_to_z.Cmp(new(big.Int).Mod(new(big.Int).Mul(commitment.a[i], statement.g), verifier.pp.N0)) != 0 {
				return false
			}
		}
	}
	return true
}

func (verifier *Verifier) VerifyWithoutCom(statement Statement, proof Proof) bool {
	verifier.tx.AppendMessage([]byte("g"), statement.g.Bytes())
	var a *big.Int

	for i := 0; i < zk.T; i++ {
		h_to_z := new(big.Int).Exp(verifier.pp.h, proof.z[i], verifier.pp.N0)
		// h^z = g^e * a % N0
		if proof.e.Bit(i) == 0 {
			a = h_to_z
		} else {
			a = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).ModInverse(statement.g, verifier.pp.N0), h_to_z), verifier.pp.N0)
		}
		verifier.tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a.Bytes())
	}

	e := new(big.Int).SetBytes(verifier.tx.ExtractBytes([]byte("e"), zk.T/8))

	if e.Cmp(proof.e) != 0 {
		return false
	}
	return true
}
