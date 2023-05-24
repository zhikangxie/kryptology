package rspdl

import (
	"crypto/rand"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

type SessionId = []byte

type Prover struct {
	curve           *curves.Curve
	basePoint       curves.Point
	A               curves.Point
	B               curves.Point
	X               curves.Point
	uniqueSessionId []byte
}

type Proof struct {
	e      curves.Scalar
	z1     curves.Scalar
	z2     curves.Scalar
	APrime curves.Point
	BPrime curves.Point
}

func NewProver(curve *curves.Curve, basePoint curves.Point, A curves.Point, B curves.Point, X curves.Point, uniqueSessionId []byte) (*Prover, error) {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}
	if A == nil {
		return nil, fmt.Errorf("point A missing")
	}
	if B == nil {
		return nil, fmt.Errorf("point B missing")
	}
	if X == nil {
		return nil, fmt.Errorf("point X missing")
	}

	return &Prover{
		curve:           curve,
		basePoint:       basePoint,
		A:               A,
		B:               B,
		X:               X,
		uniqueSessionId: uniqueSessionId,
	}, nil
}

func (p *Prover) Prove(x curves.Scalar, r curves.Scalar) (*Proof, error) {
	var err error
	result := &Proof{}

	// compute statement
	result.APrime = p.A.Mul(x).Add(p.basePoint.Mul(r))
	result.BPrime = p.B.Mul(x).Add(p.basePoint.Mul(r))

	// compute commitment
	alpha := p.curve.Scalar.Random(rand.Reader)
	beta := p.curve.Scalar.Random(rand.Reader)
	Y1 := p.basePoint.Mul(beta)
	Y2 := p.A.Mul(beta).Add(p.basePoint.Mul(alpha))
	Y3 := p.B.Mul(beta).Add(p.basePoint.Mul(alpha))

	// compute challenge
	hash := sha3.New256()
	if _, err = hash.Write(p.uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "writing salt to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(p.basePoint.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing base point to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(p.A.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing A to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(p.B.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing B to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(p.X.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing X (first part of statement) to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(result.APrime.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing A' (second part of statement) to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(result.BPrime.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing B' (third part of statement) to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(Y1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point Y1 to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(Y2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point Y2 to hash in scalar product with discrete logarithm relation proof")
	}
	if _, err = hash.Write(Y3.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point Y3 to hash in scalar product with discrete logarithm relation proof")
	}
	result.e, err = p.curve.Scalar.SetBytes(hash.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "generating challenge in scalar product with discrete logarithm relation proof")
	}

	// compute response
	result.z1 = beta.Add(result.e.Mul(x))
	result.z2 = alpha.Add(result.e.Mul(r))

	return result, nil
}

func Verify(proof *Proof, curve *curves.Curve, basePoint curves.Point, A curves.Point, B curves.Point, X curves.Point, uniqueSessionId []byte) error {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}
	if A == nil {
		return fmt.Errorf("point A missing")
	}
	if B == nil {
		return fmt.Errorf("point B missing")
	}
	if X == nil {
		return fmt.Errorf("point X missing")
	}
	var err error

	// compute commitment
	Y1 := basePoint.Mul(proof.z1).Sub(X.Mul(proof.e))
	Y2 := A.Mul(proof.z1).Add(basePoint.Mul(proof.z2)).Sub(proof.APrime.Mul(proof.e))
	Y3 := B.Mul(proof.z1).Add(basePoint.Mul(proof.z2)).Sub(proof.BPrime.Mul(proof.e))

	// compute challenge
	hash := sha3.New256()
	if _, err = hash.Write(uniqueSessionId); err != nil {
		return errors.Wrap(err, "writing salt to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(basePoint.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing base point to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(A.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing A to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(B.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing B to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(X.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing X (first part of statement) to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(proof.APrime.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing A' (second part of statement) to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(proof.BPrime.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing B' (third part of statement) to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(Y1.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point Y1 to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(Y2.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point Y2 to hash in scalar product with discrete logarithm relation verification")
	}
	if _, err = hash.Write(Y3.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point Y3 to hash in scalar product with discrete logarithm relation verification")
	}
	e, err := curve.Scalar.SetBytes(hash.Sum(nil))
	if err != nil {
		return errors.Wrap(err, "generating challenge in scalar product with discrete logarithm relation verification")
	}

	// compare challenge
	if e.Cmp(proof.e) != 0 {
		return fmt.Errorf("scalar product with discrete logarithm relation verification failed")
	}
	return nil
}
