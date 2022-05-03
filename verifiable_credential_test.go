package vc_go_sdk

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/stretchr/testify/assert"
)

type credentialSub struct {
	Id     string `json:"id,omitempty"`
	Degree string `json:"degree,omitempty"`
}

func genPrikey() (keypair.PrivateKey, keypair.PublicKey, error) {
	return keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)
}

func PackVC() (*VerifiableCredential, error) {
	contexts := []string{"https://www.w3.org/2018/credentials/examples/v1"}
	credentialId := "http://example.edu/credentials/58473"
	types := []string{"AlumniCredential"}
	credentialSubject := credentialSub{
		Id:     "did:example:ebfeb1f712ebc6f1c276e12ec21",
		Degree: "123",
	}
	issuanceTime := int64(1637549615)
	expirationDateTimestamp := int64(0)
	issuerId := "did:ont:ebfeb1f712ebc6f1c276e12ec21"
	return PackCredential(contexts, credentialId, types, credentialSubject, issuerId, nil, issuanceTime, expirationDateTimestamp)
}

func CreateCredential(pri keypair.PrivateKey, pub keypair.PublicKey) (*VerifiableCredential, error) {
	vc, err := PackVC()
	if err != nil {
		return nil, err
	}
	pk := &PublicKey{
		Id:           "",
		Type:         "SHA256withECDSA",
		PublicKeyHex: hex.EncodeToString(keypair.SerializePublicKey(pub)),
	}
	proof, err := PackCredentialProof(vc, time.Now().UTC().Unix(), PROOF_PURPOSE, pk, pri)
	if err != nil {
		return nil, err
	}
	return CreateVC(vc, proof)
}

func TestPackCredential(t *testing.T) {
	cred, err := PackVC()
	assert.Nil(t, err)
	t.Logf("cred:%v", cred)
	data, err := json.Marshal(cred)
	assert.Nil(t, err)
	vc := &VerifiableCredential{}
	err = json.Unmarshal(data, &vc)
	assert.Nil(t, err)
	t.Logf("vc:%v", vc)
	vcData, _ := json.MarshalIndent(vc, "", "    ")
	t.Logf("data:%v", string(vcData))
}

func TestVerifiableCredential_VerifyIssuer(t *testing.T) {
	pri, pub, err := genPrikey()
	assert.Nil(t, err)
	vc, err := CreateCredential(pri, pub)
	assert.Nil(t, err)
	trustedIssuers := []string{"did:ont:ebfeb1f712ebc6f1c276e12ec21"}
	assert.Equal(t, true, VerifyIssuer(vc, trustedIssuers))
}

func TestVerifiableCredential_VerifyExpirationDate(t *testing.T) {
	pri, pub, err := genPrikey()
	assert.Nil(t, err)
	vc, err := CreateCredential(pri, pub)
	assert.Nil(t, err)
	flag, err := VerifyExpirationDate(vc)
	assert.Nil(t, err)
	assert.Equal(t, true, flag)
}

func TestVerifiableCredential_VerifyIssuanceDate(t *testing.T) {
	pri, pub, err := genPrikey()
	assert.Nil(t, err)
	vc, err := CreateCredential(pri, pub)
	assert.Nil(t, err)
	flag, err := VerifyExpirationDate(vc)
	assert.Nil(t, err)
	assert.Equal(t, true, flag)
}

func TestVerifiableCredential_VerifyProof(t *testing.T) {
	pri, pub, err := genPrikey()
	assert.Nil(t, err)
	vc, err := CreateCredential(pri, pub)
	assert.Nil(t, err)
	pk := &PublicKey{
		Id:           "",
		Type:         "SHA256withECDSA",
		PublicKeyHex: hex.EncodeToString(keypair.SerializePublicKey(pub)),
	}
	flag, err := VerifyProof(vc, pk)
	assert.Nil(t, err)
	assert.Equal(t, true, flag)
}

func TestVerifyVC(t *testing.T) {
	pri, pub, err := genPrikey()
	assert.Nil(t, err)
	vc, err := CreateCredential(pri, pub)
	assert.Nil(t, err)
	trustedIssuers := []string{"did:ont:ebfeb1f712ebc6f1c276e12ec21"}
	pk := &PublicKey{
		Id:           "",
		Type:         "SHA256withECDSA",
		PublicKeyHex: hex.EncodeToString(keypair.SerializePublicKey(pub)),
	}
	verifyIssuer, verifyIssuanceDate, verifyExpirationDate, verifyProof, err := VerifyVC(vc, trustedIssuers, pk)
	assert.Nil(t, err)
	assert.Equal(t, true, verifyIssuer)
	assert.Equal(t, true, verifyIssuanceDate)
	assert.Equal(t, true, verifyExpirationDate)
	assert.Equal(t, true, verifyProof)
}
