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

func square_root_modolo(a *big.Int, p *big.Int, q *big.Int) *big.Int {
	if new(big.Int).Mod(p, big.NewInt(4)).Cmp(big.NewInt(3)) != 0 ||
		new(big.Int).Mod(q, big.NewInt(4)).Cmp(big.NewInt(3)) != 0 {
		panic("p or q not equal to 3 mod 4")
	}

	p_plus_one := new(big.Int).Add(p, crypto.One)
	q_plus_one := new(big.Int).Add(q, crypto.One)
	p_plus_one_div_four := new(big.Int).Div(p_plus_one, big.NewInt(4))
	q_plus_one_div_four := new(big.Int).Div(q_plus_one, big.NewInt(4))

	if new(big.Int).Mod(p_plus_one, big.NewInt(4)).Cmp(big.NewInt(0)) != 0 ||
		new(big.Int).Mod(q_plus_one, big.NewInt(4)).Cmp(big.NewInt(0)) != 0 {
		panic("p or q not equal to 3 mod 4")
	}

	y := new(big.Int).Mod(a, p)
	valid_square_root_modolo_p := crypto.Zero
	mod_p_pos := new(big.Int).Exp(y, p_plus_one_div_four, p)
	mod_p_neg := new(big.Int).Sub(p, mod_p_pos)

	if new(big.Int).Mod(new(big.Int).Mul(mod_p_pos, mod_p_pos), p).Cmp(y) == 0 {
		valid_square_root_modolo_p = mod_p_pos
	} else if new(big.Int).Mod(new(big.Int).Mul(mod_p_neg, mod_p_neg), p).Cmp(y) == 0 {
		valid_square_root_modolo_p = mod_p_neg
	} else {
		panic("Square root mod p not exist.")
	}

	y = new(big.Int).Mod(a, q)
	valid_square_root_modolo_q := crypto.Zero
	mod_q_pos := new(big.Int).Exp(y, q_plus_one_div_four, q)
	mod_q_neg := new(big.Int).Sub(q, mod_q_pos)

	if new(big.Int).Mod(new(big.Int).Mul(mod_q_pos, mod_q_pos), q).Cmp(y) == 0 {
		valid_square_root_modolo_q = mod_q_pos
	} else if new(big.Int).Mod(new(big.Int).Mul(mod_q_neg, mod_q_neg), q).Cmp(y) == 0 {
		valid_square_root_modolo_q = mod_q_neg
	} else {
		panic("Square root mod q not exist.")
	}

	inv_p_mod_q := new(big.Int).ModInverse(p, q)
	inv_q_mod_p := new(big.Int).ModInverse(q, p)

	vsrpqi := new(big.Int).Mul(new(big.Int).Mul(valid_square_root_modolo_p, q), inv_q_mod_p)
	vsrqpi := new(big.Int).Mul(new(big.Int).Mul(valid_square_root_modolo_q, p), inv_p_mod_q)

	z := new(big.Int).Add(vsrpqi, vsrqpi)

	return z
}

func square_root_modolo_with_jacobi_test(a *big.Int, p *big.Int, q *big.Int) *big.Int {
	z := square_root_modolo(a, p, q)

	z_flag_p := big.Jacobi(z, p)
	z_flag_q := big.Jacobi(z, q)

	if z_flag_p != 1 || z_flag_q != 1 {
		panic("z_flag_p or z_flag_q not equal to 1")
	}
	return z
}

func rpprove(st *ModStatement, ws *ModWitness) *ModProof {
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

	a := 0
	b := 0

	for i := 0; i < m; i++ {
		yp_i_choice_one := y_vec[i]
		yp_i_choice_two := new(big.Int).Mul(y_vec[i], big.NewInt(-1))
		yp_i_choice_three := new(big.Int).Mul(y_vec[i], w)
		yp_i_choice_four := new(big.Int).Mul(yp_i_choice_three, big.NewInt(-1))

		yp_i_choice_one_flag_p := big.Jacobi(yp_i_choice_one, ws.p)
		yp_i_choice_two_flag_p := big.Jacobi(yp_i_choice_two, ws.p)
		yp_i_choice_three_flag_p := big.Jacobi(yp_i_choice_three, ws.p)
		yp_i_choice_four_flag_p := big.Jacobi(yp_i_choice_four, ws.p)

		yp_i_choice_one_flag_q := big.Jacobi(yp_i_choice_one, ws.q)
		yp_i_choice_two_flag_q := big.Jacobi(yp_i_choice_two, ws.q)
		yp_i_choice_three_flag_q := big.Jacobi(yp_i_choice_three, ws.q)
		yp_i_choice_four_flag_q := big.Jacobi(yp_i_choice_four, ws.q)

		jacobi_returns_one := crypto.Zero

		if yp_i_choice_one_flag_p == 1 && yp_i_choice_one_flag_q == 1 {
			jacobi_returns_one = yp_i_choice_one
			a = 0
			b = 0
		} else if yp_i_choice_two_flag_p == 1 && yp_i_choice_two_flag_q == 1 {
			jacobi_returns_one = yp_i_choice_two
			a = 1
			b = 0
		} else if yp_i_choice_three_flag_p == 1 && yp_i_choice_three_flag_q == 1 {
			jacobi_returns_one = yp_i_choice_three
			a = 0
			b = 1
		} else if yp_i_choice_four_flag_p == 1 && yp_i_choice_four_flag_q == 1 {
			jacobi_returns_one = yp_i_choice_four
			a = 1
			b = 1
		} else {
			panic("No valid choice.")
		}

		first_root := square_root_modolo_with_jacobi_test(jacobi_returns_one, ws.p, ws.q)
		second_root := square_root_modolo(first_root, ws.p, ws.q)

		modProof.x_vec[i] = second_root
		modProof.a_vec[i] = a
		modProof.b_vec[i] = b
	}

	phi_N := new(big.Int).Mul(new(big.Int).Sub(ws.p, crypto.One), new(big.Int).Sub(ws.q, crypto.One))

	for i := 0; i < m; i++ {
		index := new(big.Int).ModInverse(st.N, phi_N)
		modProof.z_vec[i] = new(big.Int).Exp(y_vec[i], index, st.N)
	}
	modProof.w = w

	if err != nil {
		panic("ZK Rp prove")
	}

	return modProof
}

func rpverify(st *ModStatement, proof *ModProof) bool {
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
