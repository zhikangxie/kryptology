package zk

import "math/big"

func Commit(g *big.Int, h *big.Int, a *big.Int, b *big.Int, m *big.Int) *big.Int {
	// c = g^a * h^b % m
	return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(g, a, m), new(big.Int).Exp(h, b, m)), m)
}
