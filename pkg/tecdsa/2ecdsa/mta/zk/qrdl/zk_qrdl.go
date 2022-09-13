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

func NewParam(N0 *big.Int, h *big.Int) *Param {
	return &Param{N0, h}
}

func NewStatement(g *big.Int) Statement {
	return Statement{g}
}

func (st *Statement) GetStatementG() *big.Int {
	return st.g
}

func NewWitness(alpha *big.Int) Witness {
	return Witness{alpha}
}

func Prove(witness Witness, statement Statement, tx *merlin.Transcript, pp *Param) Proof {
	n := new(big.Int).Lsh(pp.N0, zk.S-1)
	tx.AppendMessage([]byte("g"), statement.g.Bytes())

	// Step 1: Commit
	beta := [zk.T]*big.Int{}
	a := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		b, _ := rand.Int(rand.Reader, n)
		beta[i] = new(big.Int).Lsh(b, 1)              // beta <$- [1, 2^s * N0) and beta is even
		a[i] = new(big.Int).Exp(pp.h, beta[i], pp.N0) // a = h^beta % N0
		tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a[i].Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

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

	return Proof{z, e}
}

func Verify(statement Statement, proof Proof, tx *merlin.Transcript, pp *Param) bool {
	tx.AppendMessage([]byte("g"), statement.g.Bytes())
	var a *big.Int

	for i := 0; i < zk.T; i++ {
		h_to_z := new(big.Int).Exp(pp.h, proof.z[i], pp.N0)
		// h^z = g^e * a % N0
		if proof.e.Bit(i) == 0 {
			a = h_to_z
		} else {
			a = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).ModInverse(statement.g, pp.N0), h_to_z), pp.N0)
		}
		tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a.Bytes())
	}

	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	if e.Cmp(proof.e) != 0 {
		return false
	}
	return true
}
