package vc_go_sdk

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/ontio/ontology-crypto/keypair"

	"github.com/stretchr/testify/assert"
)

func Presentation() (*VerifiablePresentation, error) {
	verifiableCredential, err := PackVC()
	if err != nil {
		return nil, err
	}
	credentials := make([]*VerifiableCredential, 0)
	credentials = append(credentials, verifiableCredential)
	id := "did:example:ebfeb1f712ebc6f1c276e12ec21"
	contexts := []string{"context1", "context2"}
	types := []string{"RelationshipCredential"}
	return PackPresentation(credentials, id, contexts, types, nil)
}

func TestPackPresentation(t *testing.T) {
	_, err := Presentation()
	assert.Nil(t, err)
}

func TestVerifyPresentationProof(t *testing.T) {
	presentation, err := Presentation()
	pri, pub, err := genPrikey()
	pk := &PublicKey{
		Id:           "",
		Type:         "SHA256withECDSA",
		PublicKeyHex: hex.EncodeToString(keypair.SerializePublicKey(pub)),
	}
	proof, err := PackPresentationProof(presentation, 1, "", nil, "", pk, pri)
	assert.Nil(t, err)
	proofs := make([]*Proof, 0)
	proofs = append(proofs, proof)
	vp, err := CreateVP(presentation, proofs)
	assert.Nil(t, err)
	res, err := VerifyPresentationProof(vp, 0, pk)
	assert.Nil(t, err)
	assert.Equal(t, true, res)
	result, err := VerifyPresentationCreationTime(presentation, 0, time.Now().Unix())
	assert.Nil(t, err)
	assert.Equal(t, true, result)
}
