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

func NewParam(N0 *big.Int) *Param {
	return &Param{N0}
}

func NewStatement(h *big.Int) Statement {
	return Statement{h}
}

func (st *Statement) GetStatementH() *big.Int {
	return st.h
}

func NewWitness(h_sqrt *big.Int) Witness {
	return Witness{h_sqrt}
}

func Prove(witness Witness, statement Statement, tx *merlin.Transcript, pp *Param) Proof {
	tx.AppendMessage([]byte("h"), statement.h.Bytes())

	// Step 1: Commit
	r := [zk.T]*big.Int{}
	a := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		r[i], _ = rand.Int(rand.Reader, pp.N0)
		a[i] = new(big.Int).Mod(new(big.Int).Mul(r[i], r[i]), pp.N0) // a = r^2 % N0
		tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a[i].Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 3: Prove
	z := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		// z = h_sqrt^e * r % N0
		if e.Bit(i) == 0 {
			z[i] = r[i]
		} else {
			z[i] = new(big.Int).Mod(new(big.Int).Mul(r[i], witness.h_sqrt), pp.N0)
		}
	}

	return Proof{z, e}
}

func Verify(statement Statement, proof Proof, tx *merlin.Transcript, pp *Param) bool {
	tx.AppendMessage([]byte("h"), statement.h.Bytes())
	var a *big.Int

	for i := 0; i < zk.T; i++ {
		z2 := new(big.Int).Mod(new(big.Int).Mul(proof.z[i], proof.z[i]), pp.N0)
		// a = h^-e * z^2 % N0
		if proof.e.Bit(i) == 0 {
			a = z2
		} else {
			a = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).ModInverse(statement.h, pp.N0), z2), pp.N0)
		}

		tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a.Bytes())
	}

	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	if e.Cmp(proof.e) != 0 {
		return false
	}

	return true
}
