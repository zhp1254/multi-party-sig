package sign

import (
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"io"
	"math/big"

	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

// messageHash is a wrapper around bytes to provide some domain separation.
type messageHash []byte

// WriteTo makes messageHash implement the io.WriterTo interface.
func (m messageHash) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(m)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (messageHash) Domain() string {
	return "messageHash"
}

// Signature represents the result of a Schnorr signature.
//
// This signature claims to satisfy:
//
//	z * G = R + H(R, Y, m) * Y
//
// for a public key Y.
type Signature struct {
	// R is the commitment point.
	R curve.Point
	// z is the response scalar.
	Z curve.Scalar
}

// Verify checks if a signature equation actually holds.
//
// Note that m is the hash of a message, and not the message itself.
func (sig Signature) Verify(public curve.Point, m []byte) bool {
	r, _ := sig.R.MarshalBinary()
	s, _ := sig.Z.MarshalBinary()
	PByte, _ := public.MarshalBinary()
	pubKey, err := edwards.ParsePubKey(curve.EdwardsInstance(), PByte)
	if err != nil {
		fmt.Println("(sig Signature) Verify public key err:", err)
		return false
	}

	var RByte [32]byte
	copy(RByte[:], r[:])
	return edwards.Verify(pubKey, m, edwards.EncodedBytesToBigInt(&RByte), new(big.Int).SetBytes(s))
}

func (sig Signature) Verify2(public curve.Point, m []byte) bool {
	group := public.Curve()

	challengeHash := hash.New()
	_ = challengeHash.WriteAny(sig.R, public, messageHash(m))
	challenge := sample.Scalar(challengeHash.Digest(), group)

	expected := challenge.Act(public)
	expected = expected.Add(sig.R)

	actual := sig.Z.ActOnBase()

	return expected.Equal(actual)
}

func getHash(R, P curve.Point, M []byte) curve.Scalar {
	var hm [64]byte
	var hmReduced [32]byte
	h := sha512.New()
	RByte, _ := R.MarshalBinary()
	PByte, _ := P.MarshalBinary()

	// k*G
	h.Write(RByte)
	// d*G
	h.Write(PByte)
	// 待签名的消息
	h.Write(M[:])
	// hash后的值
	h.Sum(hm[:0])
	// 64 位hash 转换成32位
	edwards25519.ScReduce(&hmReduced, &hm)
	c := R.Curve().NewScalar()
	_ = c.UnmarshalBinary(hmReduced[:])
	return c
}

func edwardsPartySign(priv, nonce, challenge curve.Scalar) curve.Scalar {
	var (
		d         []byte
		k         []byte
		hm        []byte
		hmReduced [32]byte
		s         [32]byte
	)

	d, _ = priv.MarshalBinary()
	k, _ = nonce.MarshalBinary()
	hm, _ = challenge.MarshalBinary()

	kByte := edwards.BigIntToEncodedBytes(new(big.Int).SetBytes(k))
	dByte := edwards.BigIntToEncodedBytes(new(big.Int).SetBytes(d))
	copy(hmReduced[:], hm[:])

	// dm + k
	edwards25519.ScMulAdd(&s, &hmReduced, dByte, kByte)
	sc := priv.Curve().NewScalar()
	_ = sc.UnmarshalBinary(edwards.EncodedBytesToBigInt(&s).Bytes())
	return sc
}

func edwardsPartySignVerify(R, P curve.Point, challenge, signature curve.Scalar) bool {
	var PByte [32]byte
	var CByte [32]byte

	PB, _ := P.MarshalBinary()
	RB, _ := R.MarshalBinary()
	CB, _ := challenge.MarshalBinary()
	SB, _ := signature.MarshalBinary()

	copy(PByte[:], PB)
	copy(CByte[:], CB)
	SByte := edwards.BigIntToEncodedBytes(new(big.Int).SetBytes(SB))

	var A edwards25519.ExtendedGroupElement
	if !A.FromBytes(&PByte) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	// s_i = k_i + h*d_i
	// s_i *G = k_i * G = h*d_i * G
	// s_i *G - h*d_i * G = k_i * G
	// s_i * G - h * P_i = R_i
	var newR edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&newR, &CByte, &A, SByte)

	var checkR [32]byte
	newR.ToBytes(&checkR)

	return subtle.ConstantTimeCompare(RB, checkR[:]) == 1
}