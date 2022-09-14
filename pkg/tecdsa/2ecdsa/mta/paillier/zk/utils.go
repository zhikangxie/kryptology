package zk

import "math/big"

func Commit(g *big.Int, h *big.Int, a *big.Int, b *big.Int, m *big.Int) *big.Int {
	// c = g^a * h^b % m
	return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(g, a, m), new(big.Int).Exp(h, b, m)), m)
}

func CRT(x *big.Int, y *big.Int, p *big.Int, q *big.Int, inv_p_mod_q *big.Int, inv_q_mod_p *big.Int) *big.Int {
	return new(big.Int).Add(
		new(big.Int).Mul(new(big.Int).Mul(x, q), inv_q_mod_p),
		new(big.Int).Mul(new(big.Int).Mul(y, p), inv_p_mod_q),
	)
}
