package zk

import (
	"crypto/sha256"
	"math/big"

	crypto "github.com/coinbase/kryptology/pkg/core"
)

const m = 80

type ModStatement struct {
	N *big.Int
}

type ModWitness struct {
	p *big.Int
	q *big.Int
}

type ModProof struct {
	w     *big.Int
	x_vec [m]*big.Int
	a_vec [m]int
	b_vec [m]int
	z_vec [m]*big.Int
}

func GenPQ(bits uint) (*big.Int, *big.Int) {
	values := make(chan *big.Int, 2)
	errors := make(chan error, 2)

	var p, q *big.Int

	for p == q {
		for range []int{1, 2} {
			go func() {
				value, err := crypto.GenerateSafePrime(bits)
				values <- value
				errors <- err
			}()
		}

		for _, err := range []error{<-errors, <-errors} {
			if err != nil {
				panic("p or q gen fail")
			}
		}

		p, q = <-values, <-values
	}
	return p, q
}

func NewRPStatement(N *big.Int) *ModStatement {
	st := &ModStatement{}
	st.N = N
	return st
}

func NewRPWitness(p *big.Int, q *big.Int) *ModWitness {
	ws := &ModWitness{}
	ws.p = p
	ws.q = q
	return ws
}

func square_root_modolo(a *big.Int, p *big.Int, q *big.Int) *big.Int {
	inv_p_mod_q := new(big.Int).ModInverse(p, q)
	inv_q_mod_p := new(big.Int).ModInverse(q, p)

	vsrpqi := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).ModSqrt(a, p), q), inv_q_mod_p)
	vsrqpi := new(big.Int).Mul(new(big.Int).Mul(new(big.Int).ModSqrt(a, q), p), inv_p_mod_q)

	z := new(big.Int).Add(vsrpqi, vsrqpi)

	return z
}

func RPProve(st *ModStatement, ws *ModWitness) *ModProof {
	var err error
	var w *big.Int
	//m := 80 // soundness error
	var y_vec [m]*big.Int

	modProof := &ModProof{}

	// Sample a random w in Zq and which satisfy Jacobi symbol (w | N) = -1
	for {
		w, err = crypto.Rand(st.N)
		if big.Jacobi(w, st.N) == -1 {
			break
		}
	}

	for i := 0; i < m; i++ {
		sum := sha256.Sum256(append(w.Bytes(), byte(i)))
		tmp := new(big.Int).SetBytes(sum[:])
		y_vec[i] = new(big.Int).Mod(tmp, st.N)
	}

	phi_N := new(big.Int).Mul(new(big.Int).Sub(ws.p, crypto.One), new(big.Int).Sub(ws.q, crypto.One))
	index := new(big.Int).ModInverse(st.N, phi_N)
	v1 := [2]*big.Int{big.NewInt(1), big.NewInt(-1)}
	v2 := [2]*big.Int{big.NewInt(1), w}
	for i := 0; i < m; i++ {
		modProof.z_vec[i] = new(big.Int).Exp(y_vec[i], index, st.N)
	Outside:
		for a := 0; a <= 1; a++ {
			for b := 0; b <= 1; b++ {
				y := new(big.Int).Mul(new(big.Int).Mul(y_vec[i], v1[a]), v2[b])
				if big.Jacobi(y, ws.p) == 1 && big.Jacobi(y, ws.q) == 1 {
					modProof.x_vec[i] = square_root_modolo(square_root_modolo(y, ws.p, ws.q), ws.p, ws.q)
					modProof.a_vec[i] = a
					modProof.b_vec[i] = b
					break Outside
				}
			}
		}
	}

	modProof.w = w

	if err != nil {
		panic("ZK Rp prove")
	}

	return modProof
}

func RPVerify(st *ModStatement, proof *ModProof) bool {
	res := true
	var y_vec [m]*big.Int

	//m := 80

	for i := 0; i < m; i++ {
		sum := sha256.Sum256(append(proof.w.Bytes(), byte(i)))
		tmp := new(big.Int).SetBytes(sum[:])
		y_vec[i] = new(big.Int).Mod(tmp, st.N)
	}

	for i := 0; i < m; i++ {

		lhs := new(big.Int).Exp(proof.z_vec[i], st.N, st.N)
		rhs := y_vec[i]

		if lhs.Cmp(rhs) != 0 {
			//panic("lhs not equal rhs")
			res = false
		}

		lhs = new(big.Int).Exp(proof.x_vec[i], big.NewInt(4), st.N)
		rhs = y_vec[i]

		if proof.a_vec[i] == 1 && proof.b_vec[i] == 0 {
			rhs = new(big.Int).Mod(new(big.Int).Mul(y_vec[i], big.NewInt(-1)), st.N)
		}

		if proof.a_vec[i] == 0 && proof.b_vec[i] == 1 {
			rhs = new(big.Int).Mod(new(big.Int).Mul(y_vec[i], proof.w), st.N)
		}

		if proof.a_vec[i] == 1 && proof.b_vec[i] == 1 {
			tmp := new(big.Int).Mod(new(big.Int).Mul(y_vec[i], big.NewInt(-1)), st.N)
			rhs = new(big.Int).Mod(new(big.Int).Mul(tmp, proof.w), st.N)
		}

		if lhs.Cmp(rhs) != 0 {
			//panic("lhs not equal rhs")
			res = false
		}
	}

	return res
}
