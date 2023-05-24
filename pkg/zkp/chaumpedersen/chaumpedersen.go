package chaumpedersen

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

type Commitment = []byte
type SessionId = []byte

type Prover struct {
	curve           *curves.Curve
	basePoint1      curves.Point
	basePoint2      curves.Point
	uniqueSessionId []byte
}

type Proof struct {
	C          curves.Scalar
	S          curves.Scalar
	Statement1 curves.Point
	Statement2 curves.Point
}

// we allow basePoint1 to be nil, in which case it is auto-assigned to be the group's default generator
// we do NOT allow basePoint2 to be nil

func NewProver(curve *curves.Curve, basePoint1 curves.Point, basePoint2 curves.Point, uniqueSessionId []byte) (*Prover, error) {
	if basePoint1 == nil {
		basePoint1 = curve.NewGeneratorPoint()
	}
	if basePoint2 == nil {
		return nil, fmt.Errorf("base point 2 missing")
	}
	return &Prover{
		curve:           curve,
		basePoint1:      basePoint1,
		basePoint2:      basePoint2,
		uniqueSessionId: uniqueSessionId,
	}, nil
}

func (p *Prover) Prove(x curves.Scalar) (*Proof, error) {
	var err error
	result := &Proof{}
	result.Statement1 = p.basePoint1.Mul(x)
	result.Statement2 = p.basePoint2.Mul(x)

	// commit
	k := p.curve.Scalar.Random(rand.Reader)
	K1 := p.basePoint1.Mul(k)
	K2 := p.basePoint2.Mul(k)

	// challenge
	hash := sha3.New256()
	if _, err = hash.Write(p.uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "writing salt to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(p.basePoint1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing basePoint1 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(p.basePoint2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing basePoint2 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(result.Statement1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing statement1 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(result.Statement2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing statement2 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(K1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point K1 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(K2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point K2 to hash in chaum-pedersen proof")
	}
	result.C, err = p.curve.Scalar.SetBytes(hash.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "generating challenge in chaum-pedersen proof")
	}

	// response
	result.S = result.C.Mul(x).Add(k)

	return result, nil
}

func (p *Prover) ProveWithStatement(statement1 curves.Point, statement2 curves.Point, x curves.Scalar) (*Proof, error) {
	var err error
	result := &Proof{}
	result.Statement1 = statement1
	result.Statement2 = statement2

	// commit
	k := p.curve.Scalar.Random(rand.Reader)
	K1 := p.basePoint1.Mul(k)
	K2 := p.basePoint2.Mul(k)

	// challenge
	hash := sha3.New256()
	if _, err = hash.Write(p.uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "writing salt to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(p.basePoint1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing basePoint1 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(p.basePoint2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing basePoint2 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(result.Statement1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing statement1 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(result.Statement2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing statement2 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(K1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point K1 to hash in chaum-pedersen proof")
	}
	if _, err = hash.Write(K2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point K2 to hash in chaum-pedersen proof")
	}
	result.C, err = p.curve.Scalar.SetBytes(hash.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "generating challenge in chaum-pedersen proof")
	}

	// response
	result.S = result.C.Mul(x).Add(k)

	return result, nil
}

// we allow basePoint1 to be nil, in which case it is auto-assigned to be the group's default generator
// we do NOT allow basePoint2 to be nil

func Verify(proof *Proof, curve *curves.Curve, basePoint1 curves.Point, basePoint2 curves.Point, uniqueSessionId []byte) error {
	if basePoint1 == nil {
		basePoint1 = curve.NewGeneratorPoint()
	}
	if basePoint2 == nil {
		return fmt.Errorf("base point 2 missing")
	}
	var err error

	K1 := basePoint1.Mul(proof.S).Add(proof.Statement1.Mul(proof.C.Neg()))
	K2 := basePoint2.Mul(proof.S).Add(proof.Statement2.Mul(proof.C.Neg()))

	hash := sha3.New256()
	if _, err = hash.Write(uniqueSessionId); err != nil {
		return errors.Wrap(err, "writing salt to hash in chaum-pedersen verification")
	}
	if _, err = hash.Write(basePoint1.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing basePoint1 to hash in chaum-pedersen verification")
	}
	if _, err = hash.Write(basePoint2.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing basePoint2 to hash in chaum-pedersen verification")
	}
	if _, err = hash.Write(proof.Statement1.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing statement1 to hash in chaum-pedersen verification")
	}
	if _, err = hash.Write(proof.Statement2.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing statement2 to hash in chaum-pedersen verification")
	}
	if _, err = hash.Write(K1.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point K1 to hash in chaum-pedersen verification")
	}
	if _, err = hash.Write(K2.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point K2 to hash in chaum-pedersen verification")
	}
	if subtle.ConstantTimeCompare(proof.C.Bytes(), hash.Sum(nil)) != 1 {
		return fmt.Errorf("chaum-pedersen verification failed")
	}
	return nil
}

func (p *Prover) ComProve(x curves.Scalar) (*Proof, Commitment, error) {
	proof, err := p.Prove(x)
	if err != nil {
		return nil, nil, err
	}

	hash := sha3.New256()
	if _, err = hash.Write(proof.C.Bytes()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.S.Bytes()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.Statement1.ToAffineCompressed()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.Statement2.ToAffineCompressed()); err != nil {
		return nil, nil, err
	}

	return proof, hash.Sum(nil), nil
}

func (p *Prover) ComProveWithStatement(statement1 curves.Point, statement2 curves.Point, x curves.Scalar) (*Proof, Commitment, error) {
	proof, err := p.ProveWithStatement(statement1, statement2, x)
	if err != nil {
		return nil, nil, err
	}

	hash := sha3.New256()
	if _, err = hash.Write(proof.C.Bytes()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.S.Bytes()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.Statement1.ToAffineCompressed()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.Statement2.ToAffineCompressed()); err != nil {
		return nil, nil, err
	}

	return proof, hash.Sum(nil), nil
}

func DeComVerify(proof *Proof, commitment Commitment, curve *curves.Curve, basePoint1 curves.Point, basePoint2 curves.Point, uniqueSessionId []byte) error {
	hash := sha3.New256()
	if _, err := hash.Write(proof.C.Bytes()); err != nil {
		return err
	}
	if _, err := hash.Write(proof.S.Bytes()); err != nil {
		return err
	}
	if _, err := hash.Write(proof.Statement1.ToAffineCompressed()); err != nil {
		return err
	}
	if _, err := hash.Write(proof.Statement2.ToAffineCompressed()); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), commitment) != 1 {
		return fmt.Errorf("initial hash decommitment failed")
	}
	return Verify(proof, curve, basePoint1, basePoint2, uniqueSessionId)
}
