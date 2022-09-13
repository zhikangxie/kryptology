package zk_r_p

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk"
	"github.com/gtank/merlin"
)

// Nothing needs to be agreed beforehand
type Agreed struct {
}

type Proof struct {
	w *big.Int

	x [zk.T]*big.Int
	a [zk.T]bool
	b [zk.T]bool
	z [zk.T]*big.Int
}

// N
type Statement = big.Int

type Witness struct {
	p *big.Int
	q *big.Int
}

func NewWitness(p *big.Int, q *big.Int) *Witness {
	return &Witness{p, q}
}

func square_root_modolo(a *big.Int, p *big.Int, q *big.Int) *big.Int {
	inv_p_mod_q := new(big.Int).ModInverse(p, q)
	inv_q_mod_p := new(big.Int).ModInverse(q, p)

	vsrpqi := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).ModSqrt(a, p), q), inv_q_mod_p)
	vsrqpi := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).ModSqrt(a, q), p), inv_p_mod_q)

	z := new(big.Int).Add(vsrpqi, vsrqpi)

	return z
}

func Prove(tx *merlin.Transcript, witness *Witness, N *Statement) *Proof {
	tx.AppendMessage([]byte("N"), N.Bytes()) // Strong Fiat-Shamir

	// Step 1: Commit
	var w *big.Int
	for {
		w, _ = rand.Int(rand.Reader, N)
		if big.Jacobi(w, N) == -1 {
			break
		}
	}
	tx.AppendMessage([]byte("w"), w.Bytes())

	// Step 2: Challenge (Fiat-Shamir)
	y := [zk.T]*big.Int{}
	t := big.NewInt(0)
	tt := big.NewInt(0)
	for i := 0; i < zk.T; {
		if tt.Cmp(N) == -1 {
			v := new(big.Int).SetBytes(tx.ExtractBytes([]byte(fmt.Sprintf("y[%d]", i)), zk.N_BITS/8+1))
			vv := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), zk.N_BITS+8), big.NewInt(1))
			t = new(big.Int).Add(new(big.Int).Lsh(t, zk.N_BITS+8), v)
			tt = new(big.Int).Add(new(big.Int).Lsh(tt, zk.N_BITS+8), vv)
		} else {
			y[i] = new(big.Int).Mod(t, N)
			t = new(big.Int).Div(t, N)
			tt = new(big.Int).Div(tt, N)
			i += 1
		}
	}

	// Step 3: Prove
	x := [zk.T]*big.Int{}
	a := [zk.T]bool{}
	b := [zk.T]bool{}
	z := [zk.T]*big.Int{}
	phi_N := new(big.Int).Mul(new(big.Int).Sub(witness.p, big.NewInt(1)), new(big.Int).Sub(witness.q, big.NewInt(1)))
	index := new(big.Int).ModInverse(N, phi_N)
	for i := 0; i < zk.T; i++ {
		z[i] = new(big.Int).Exp(y[i], index, N)
	Outside:
		for _, a[i] = range []bool{false, true} {
			for _, b[i] = range []bool{false, true} {
				y := y[i]
				if a[i] {
					y = new(big.Int).Neg(y)
				}
				if b[i] {
					y = new(big.Int).Mul(y, w)
				}
				if big.Jacobi(y, witness.p) == 1 && big.Jacobi(y, witness.q) == 1 {
					x[i] = square_root_modolo(square_root_modolo(y, witness.p, witness.q), witness.p, witness.q)
					break Outside
				}
			}
		}
	}

	return &Proof{w, x, a, b, z}
}

func Verify(tx *merlin.Transcript, N *Statement, proof *Proof) bool {
	tx.AppendMessage([]byte("N"), N.Bytes()) // Strong Fiat-Shamir

	tx.AppendMessage([]byte("w"), proof.w.Bytes())

	// Step 2: Challenge (Fiat-Shamir)
	y := [zk.T]*big.Int{}
	t := big.NewInt(0)
	tt := big.NewInt(0)
	for i := 0; i < zk.T; {
		if tt.Cmp(N) == -1 {
			v := new(big.Int).SetBytes(tx.ExtractBytes([]byte(fmt.Sprintf("y[%d]", i)), zk.N_BITS/8+1))
			vv := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), zk.N_BITS+8), big.NewInt(1))
			t = new(big.Int).Add(new(big.Int).Lsh(t, zk.N_BITS+8), v)
			tt = new(big.Int).Add(new(big.Int).Lsh(tt, zk.N_BITS+8), vv)
		} else {
			y[i] = new(big.Int).Mod(t, N)
			t = new(big.Int).Div(t, N)
			tt = new(big.Int).Div(tt, N)
			i += 1
		}
	}

	// Step 4: Verify
	if N.ProbablyPrime(64) {
		return false
	}
	for i := 0; i < zk.T; i++ {
		if new(big.Int).Exp(proof.z[i], N, N).Cmp(y[i]) != 0 {
			return false
		}
		y := y[i]
		if proof.a[i] {
			y = new(big.Int).Neg(y)
		}
		if proof.b[i] {
			y = new(big.Int).Mul(y, proof.w)
		}
		y = new(big.Int).Mod(y, N)
		if new(big.Int).Exp(proof.x[i], big.NewInt(4), N).Cmp(y) != 0 {
			return false
		}
	}

	return true
}
