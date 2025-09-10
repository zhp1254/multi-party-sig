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
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, taproot.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(taproot.Signature)
		assert.True(t, public.Verify(signature, m), "expected valid signature")
	}
}

func TestSignTaproot(t *testing.T) {
	group := curve.Secp256k1{}
	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	publicPoint := secret.ActOnBase()
	if !publicPoint.(*curve.Secp256k1Point).HasEvenY() {
		secret.Negate()
	}
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := taproot.PublicKey(publicPoint.(*curve.Secp256k1Point).XBytes())
	steakHash := sha256.New()
	_, _ = steakHash.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	steak := steakHash.Sum(nil)
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]*curve.Secp256k1Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group)).(*curve.Secp256k1Scalar)
	}

	verificationShares := make(map[party.ID]*curve.Secp256k1Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase().(*curve.Secp256k1Point)
	}

	var newPublicKey []byte
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.TaprootConfig{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: verificationShares,
		}
		result, _ = result.DeriveChild(1)
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		tapRootPublicKey, err := curve.Secp256k1{}.LiftX(newPublicKey)
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