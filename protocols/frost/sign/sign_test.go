package sign

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/decred/dcrd/dcrec/edwards"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/frost/keygen"
)

func checkOutput(t *testing.T, rounds []round.Session, public curve.Point, m []byte) {
	for _, r := range rounds {
		//fmt.Println(r.(*round.Abort).Err)
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, Signature{}, resultRound.Result, "expected signature result")
		signature := resultRound.Result.(Signature)
		assert.True(t, signature.Verify(public, m), "expected valid signature")
	}
}

func TestSign(t *testing.T) {
	group := curve.TwistedEdwardsCurve{}

	N := 3
	threshold := 2

	partyIDs := test.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := secret.ActOnBase()
	steak := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]curve.Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group))
	}

	verificationShares := make(map[party.ID]curve.Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase()
	}

	var newPublicKey curve.Point
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.Config{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: party.NewPointMap(verificationShares),
			ChainKey:           chainKey,
		}
		//result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		r, err := StartSignCommon(false, result, partyIDs, steak)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutput(t, rounds, newPublicKey, steak)
}

func checkOutputTaproot(t *testing.T, rounds []round.Session, public taproot.PublicKey, m []byte) {
	for _, r := range rounds {
		//fmt.Println(r.(*round.Abort).Err)
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, taproot.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(taproot.Signature)
		assert.True(t, public.Verify(signature, m), "expected valid signature")
	}
}

func TestSignTaproot(t *testing.T) {
	group := curve.Secp256k1{}
	N := 3
	threshold := 2

	partyIDs := test.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	publicPoint := secret.ActOnBase()
	if !publicPoint.(*curve.Secp256k1Point).HasEvenY() {
		secret.Negate()
	}
	f := polynomial.NewPolynomial(group, threshold, secret)
	//publicKey := taproot.PublicKey(publicPoint.(*curve.Secp256k1Point).XBytes())
	steakHash := sha256.New()
	_, _ = steakHash.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	steak := steakHash.Sum(nil)
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]*curve.Secp256k1Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group)).(*curve.Secp256k1Scalar)
	}

	//verificationShares := make(map[party.ID]*curve.Secp256k1Point, N)
	/*for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase().(*curve.Secp256k1Point)
	}*/

	verification := make(map[party.ID]*curve.Secp256k1Point, N)
	//Lambdas := polynomial.Lagrange(group, partyIDs)

	kes := map[party.ID]string {
		partyIDs[0]: "f5ed0aacea7d8be27b72e95d599fd47bffe7749266c19590af13e15906c7d419",
		partyIDs[1]: "40b8959c0c07a4d6ac8992619d0a0cebb183a728d8e5908e5945a92c05481b4c",
		partyIDs[2]: "fa67d381e13f580939c7cb929d464f38f79cfd8986c8dd1094df2c0f9b363e07",
	}

	pub := group.NewPoint().(*curve.Secp256k1Point)
	s := group.NewScalar().(*curve.Secp256k1Scalar)
	for id, _ := range privateShares {
		//s_i := group.NewScalar().Set(Lambdas[id]).Mul(v)
		fmt.Println(kes[id], id)
		s_i_b, _ := hex.DecodeString(kes[id])
		s_i := group.NewScalar()
		fmt.Println(s_i.UnmarshalBinary(s_i_b), id)
		privateShares[id] = s_i.(*curve.Secp256k1Scalar)
		//s_i_G := group.NewScalar().Set(Lambdas[id]).Act(verificationShares[id])
		s_i_G := s_i.ActOnBase()
		verification[id] = s_i_G.(*curve.Secp256k1Point)

		pub = (pub.Add(s_i_G)).(*curve.Secp256k1Point)
		s.Add(privateShares[id])
	}
	pub1 := s.ActOnBase().(*curve.Secp256k1Point)
	fmt.Println(pub.Equal(pub1), " =========<")

	if !pub.HasEvenY() {
		fmt.Println("!pub.HasEvenY()")
		for id, v := range privateShares {
			v.Negate()
			verification[id] = verification[id].Negate().(*curve.Secp256k1Point)
		}
	}
	//steak, _ = hex.DecodeString("5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953")

	tapRootPublicKeyB, _ := pub.MarshalBinary()
	fmt.Println("tapRootPublicKeyB: ",  hex.EncodeToString(tapRootPublicKeyB))

	var newPublicKey []byte
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.TaprootConfig{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          pub.XBytes(),
			PrivateShare:       privateShares[id],
			VerificationShares: verification,
		}

		newPublicKey = result.PublicKey
		/*result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}*/
		tapRootPublicKey, err := curve.Secp256k1{}.LiftX(newPublicKey)
		//fmt.Println("hex.tapRootPublicKey", hex.EncodeToString(tapRootPublicKeyB))
		//fmt.Println("hex.tapRootPublicKey", hex.EncodeToString(newPublicKey))
		genericVerificationShares := make(map[party.ID]curve.Point)
		for k, v := range result.VerificationShares {
			genericVerificationShares[k] = v
		}
		require.NoError(t, err)
		normalResult := &keygen.Config{
			ID:                 result.ID,
			Threshold:          result.Threshold,
			PrivateShare:       result.PrivateShare,
			PublicKey:          tapRootPublicKey,
			VerificationShares: party.NewPointMap(genericVerificationShares),
		}
		r, err := StartSignCommon(true, normalResult, partyIDs, steak)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutputTaproot(t, rounds, newPublicKey, steak)
}

func TestSignCheck(t *testing.T)  {
	d1, _ := hex.DecodeString("03eb4cef171d2a709dcc7dca78889f8216fca0b7b5a170e3a6588b7553ade9bd")
	d2, _ := hex.DecodeString("02668f129985a7f2c0f79fbd2c67d86c603724555ac627f06babed1432683ff5")
	d3, _ := hex.DecodeString("0b1e68c9c3fe5d3a80847f61f58234f6d17711e92c23530d3d562fd832c677f4")

	k1, _ := hex.DecodeString("0c84a56548c97387c80827a4910397cb42da6d66285f44bb0ce065386d2fb4df")
	k2, _ := hex.DecodeString("0becd683c56db356a59cb1ecb1a3a03c7178a386ea85c45f3707d0be852afd1d")
	k3, _ := hex.DecodeString("0622984d4a8e68396bdac32a8ff685a583c5821ae1baefcd6ac67259db697e79")

	pub := "01454bb4b99fbe9bc8cf502d36323f35001d58a7a40aae2720d4020e270b27ca"
	R := "1be801b24cadc2a802bc9ecca47c56b7615e65ac6cf8fd25ffd4ebec3f44a478"

	priv1 := new(big.Int).SetBytes(d1)
	priv2 := new(big.Int).SetBytes(d2)
	priv3 := new(big.Int).SetBytes(d3)

	priv := new(big.Int).Add(priv1, priv2)
	priv.Add(priv, priv3)

	c := curve.EdwardsInstance()
	priv.Mod(priv, c.N)
	px, py := c.ScalarBaseMult(priv.Bytes())
	fmt.Println(hex.EncodeToString(edwards.BigIntPointToEncodedBytes(px, py)[:]))
	fmt.Println(pub)


	bk1 := new(big.Int).SetBytes(k1)
	bk2 := new(big.Int).SetBytes(k2)
	bk3 := new(big.Int).SetBytes(k3)

	k := new(big.Int).Add(bk1, bk2)
	k.Add(k, bk3)

	priv.Mod(k, c.N)
	kx, ky := c.ScalarBaseMult(k.Bytes())
	fmt.Println(hex.EncodeToString(edwards.BigIntPointToEncodedBytes(kx, ky)[:]))
	fmt.Println(R)
}

func TestTaproot(t *testing.T)  {

 	PByte, _ := hex.DecodeString("1a6508ccf9310823b24285bddf5d41669e0f2e0ec2b62ca7a95d53e043550734")

 	K2Byte, _ := hex.DecodeString("f4d837da1ccebe5a82ba458d0ea97c82851592eaac745023cc2b61b79284c573")
	D2Byte, _ := hex.DecodeString("f5ed0aacea7d8be27b72e95d599fd47bffe7749266c19590af13e15906c7d419")

	K1Byte, _ := hex.DecodeString("eeb95637dc72fbcc0a3da853438fef52d654e4cb68e223a1c36dc8de6e1f3b2b")
	D1Byte, _ := hex.DecodeString("fa67d381e13f580939c7cb929d464f38f79cfd8986c8dd1094df2c0f9b363e07")

	K3Byte, _ := hex.DecodeString("16fc6744749067c5207c045a5afa2d0363248c92391985f83035ad70e113c18e")
	D3Byte, _ := hex.DecodeString("40b8959c0c07a4d6ac8992619d0a0cebb183a728d8e5908e5945a92c05481b4c")

	MByte, _ := hex.DecodeString("5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953")
	RxByte, _ := hex.DecodeString("02f2e9d006218f3f07b515384f63e407186b71b6ae854427fd1bce7eb477bcea16")

	d1,d2,d3,k1,k2,k3 := new(curve.Secp256k1Scalar),new(curve.Secp256k1Scalar),new(curve.Secp256k1Scalar),new(curve.Secp256k1Scalar),new(curve.Secp256k1Scalar),new(curve.Secp256k1Scalar)
	fmt.Println( d1.UnmarshalBinary(D1Byte))
	fmt.Println(d2.UnmarshalBinary(D2Byte))
	fmt.Println(d3.UnmarshalBinary(D3Byte))

	fmt.Println(k1.UnmarshalBinary(K1Byte))
	fmt.Println(k2.UnmarshalBinary(K2Byte))
	fmt.Println(k3.UnmarshalBinary(K3Byte))

	d,k := new(curve.Secp256k1Scalar),new(curve.Secp256k1Scalar)
	d.Add(d1)
	d.Add(d2)
	d.Add(d3)

	k.Add(k1)
	k.Add(k2)
	k.Add(k3)

	R := k.ActOnBase()
	P := d.ActOnBase()
	fmt.Println(" private key: ", d)
	fmt.Println(" K key: ", k)

	if !R.(*curve.Secp256k1Point).HasEvenY() {
		fmt.Println("R.(*curve.Secp256k1Point).HasEvenY()")
		k.Negate()
	}
	if !P.(*curve.Secp256k1Point).HasEvenY() {
		fmt.Println("P.(*curve.Secp256k1Point).HasEvenY()")
		d.Negate()
	}

	fmt.Println(hex.EncodeToString(R.(*curve.Secp256k1Point).XBytes()), hex.EncodeToString(RxByte))
	fmt.Println(hex.EncodeToString(P.(*curve.Secp256k1Point).XBytes()), hex.EncodeToString(PByte))

	cHash := taproot.TaggedHash("BIP0340/challenge", R.(*curve.Secp256k1Point).XBytes(),
		P.(*curve.Secp256k1Point).XBytes(),
		MByte)

	fmt.Println("cHash: ", hex.EncodeToString(cHash))

	M := R.Curve().NewScalar()
	fmt.Println(M.UnmarshalBinary(cHash))
	fmt.Println("M.ActP: ", M.Act(P))

	z := R.Curve().NewScalar().Set(M).Mul(d)
	fmt.Println("M *D: ",z)

	z.Add(k)
	sig := taproot.Signature(make([]byte, 0, taproot.SignatureLen))
	sig = append(sig, R.(*curve.Secp256k1Point).XBytes()...)
	zBytes, err := z.MarshalBinary()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("z.MarshalBinary() ", hex.EncodeToString(zBytes))
	sig = append(sig, zBytes[:]...)

	taprootPub := taproot.PublicKey(P.(*curve.Secp256k1Point).XBytes())
	fmt.Println("taprootPub : ", P)
	fmt.Println(taprootPub.Verify(sig, MByte))

}