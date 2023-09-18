package verify

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"
)

func Verify(curve *curves.Curve, basePoint curves.Point, pk curves.Point, message []byte, r curves.Scalar, s curves.Scalar) error {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}

	R := pk.Mul(s).Sub(basePoint.Mul(r))

	h := curve.Scalar.Hash(message)

	RAffine := R.ToAffineCompressed()
	rx, err := curve.Scalar.SetBigInt(new(big.Int).SetBytes(RAffine[1 : 1+(len(RAffine)>>1)]))
	if err != nil {
		panic("when computing x-coordinate of R")
	}

	if r.Cmp(rx.Add(h)) != 0 {
		return fmt.Errorf("verification failed")
	}

	return nil
}

func ECDSAVerify(curve *curves.Curve, basePoint curves.Point, pk curves.Point, message []byte, r curves.Scalar, s curves.Scalar) error {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}

	h := curve.Scalar.Hash(message)

	sInvert, err := s.Invert()
	if err != nil {
		panic("failed when inverting s")
	}

	R := basePoint.Mul(h).Add(pk.Mul(r)).Mul(sInvert)

	RAffine := R.ToAffineCompressed()
	rx, err := curve.Scalar.SetBigInt(new(big.Int).SetBytes(RAffine[1 : 1+(len(RAffine)>>1)]))
	if err != nil {
		panic("when computing x-coordinate of R")
	}

	if r.Cmp(rx) != 0 {
		return fmt.Errorf("verification failed")
	}

	return nil
}
