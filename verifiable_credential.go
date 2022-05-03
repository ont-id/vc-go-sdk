package vc_go_sdk

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jinzhu/copier"

	uuid "github.com/satori/go.uuid"
)

// @title    PackCredential
// @description Collect all the information except proofs to form a credential without the Proof field.
// @param     contexts		[]string		"list of contexts, all of the items are URIs, can be omitted"
// @param     credentialId	string			"must be a URI, the identifier of new credential, will automatically generate a UUID if it is omitted"
// @param     types		[]string		"list of types for the expression of type information, all of the items are URIs, can be omitted"
// @param     credentialSubject	interface{}		"claims about one or more subjects to be verified by the issuer in JSON format"
// @param     issuerId		interface{}		"a URI or an Object to express the issuer information"
// @param     credentialStatus	*CredentialStatus	"a struct that indicates how to deal with the status of this credential"
// @param     issuanceTime	int64			"a unix timestamp to indicate the issuance time, use current time if it is omitted"
// @param     expirationTime	int64			"a unix timestamp to indicate the expiration time, will be a bank if it is omitted"
// @return    a credential without the proof filed.
func PackCredential(contexts []string, credentialId string, types []string, credentialSubject, issuerId interface{}, credentialStatus *CredentialStatus, issuanceTime, expirationDateTimestamp int64) (*VerifiableCredential, error) {
	for _, context := range contexts {
		if !checkUri(context) {
			return nil, fmt.Errorf("data format not uri")
		}
	}
	if !checkUri(credentialId) {
		return nil, fmt.Errorf("field not valid")
	}
	if credentialSubject == nil || issuerId == nil {
		return nil, fmt.Errorf("params can't nil")
	}
	if !checkIssuerVaild(issuerId) || !checkCredentialSubject(credentialSubject) {
		return nil, fmt.Errorf("issuerId or credentialSubject invalid")
	}
	if credentialStatus != nil {
		if !checkUri(credentialStatus.Id) {
			return nil, fmt.Errorf("data format not uri")
		}
	}
	credential := new(VerifiableCredential)
	if credentialId == "" {
		credential.Id = UUID_PREFIX + uuid.NewV4().String()
	} else {
		credential.Id = credentialId
	}
	credential.CredentialStatus = credentialStatus
	credential.Context = append(DefaultContext, contexts...)
	credential.Type = append(DefaultCredentialType, types...)
	credential.Issuer = issuerId
	var issuanceDateTime string
	if issuanceTime == 0 {
		issuanceTime = time.Now().UTC().Unix()
		issuanceDateTime = time.Unix(issuanceTime, 0).UTC().Format("2006-01-02T15:04:05Z")
	} else {
		issuanceDateTime = time.Unix(issuanceTime, 0).UTC().Format("2006-01-02T15:04:05Z")
	}

	credential.IssuanceDate = issuanceDateTime

	if expirationDateTimestamp != 0 {
		if issuanceTime >= expirationDateTimestamp {
			return nil, fmt.Errorf("CreateCredential, now is after expirationDateTimestamp")
		}
		expirationDate := time.Unix(expirationDateTimestamp, 0).UTC().Format("2006-01-02T15:04:05Z")
		credential.ExpirationDate = expirationDate
	}
	credential.CredentialSubject = credentialSubject
	return credential, nil
}

// @title    PackCredentialProof
// @description   Generate a proof from a credential without proofs. A credential can be attached the issuer's proof to form a verifiable credential.
// @param     credential	*VerifiableCredential	    "a credential need to be attached with the proof field"
// @param     created		int64			    "a unix timestamp to indicate the creation time, will use the current time if it is omitted"
// @param     proofPurpose	stirng			    "the purose of this proof"
// @param     pk		*Publickey		    "the signer's public key"
// @param     signer		crypto.PrivateKey	    "the signer's private key"
// @return    a proof that make the presentation verifiable.
func PackCredentialProof(credential *VerifiableCredential, created int64, proofPurpose ProofPurpose, pk *PublicKey, signer crypto.PrivateKey) (*Proof, error) {
	proof := packProof(created, "", nil, proofPurpose, pk)
	credentialData := VerifiableCredential{}
	err := copier.Copy(&credentialData, credential)
	if err != nil {
		return nil, err
	}
	credentialData.Proof = proof
	msg, err := json.Marshal(credentialData)
	if err != nil {
		return nil, fmt.Errorf("PackCredentialProof json marshal credential err: %s", err)
	}
	sigData, err := signData(proof.Type, signer, msg)
	if err != nil {
		return nil, fmt.Errorf("PackCredentialProof error: %s", err)
	}
	proof.Hex = hex.EncodeToString(sigData)
	return proof, nil
}

// @title    CreateVC
// @description   Generate a verifiable credential using a credential without the proof field and the issuer's proof that make this presentation verifiable.
// @param     credential	*VerifiableCredential	    "a credential need to be attached with the proof field"
// @param     proof		*Proof			    "the issuer's proof"
// @return    a verifiable credential

func CreateVC(credential *VerifiableCredential, proof *Proof) (*VerifiableCredential, error) {
	credential.Proof = proof
	return credential, nil
}

// @title    VerifyIssuer
// @description Verify that a credential's issuer is in the trust list or not
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @param     TrustedIssuers	[]string		    "a list of trusted issuers, each item is a URI"
// @return    true if the issuer is trusted.
func VerifyIssuer(credential *VerifiableCredential, TrustedIssuers []string) bool {
	for _, v := range TrustedIssuers {
		if credential.Issuer == v {
			return true
		}
	}
	return false
}

// @title    VerifyIssuanceDate
// @description Verify that a credential is effective or not.
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @return    true if the VC is  effective.
func VerifyIssuanceDate(credential *VerifiableCredential) (bool, error) {
	if credential.ExpirationDate != "" {
		expirationDate, err := time.Parse("2006-01-02T15:04:05Z", credential.ExpirationDate)
		if err != nil {
			return false, fmt.Errorf("VerifyExpirationDate error: %s", err)
		}
		if time.Now().UTC().Unix() > expirationDate.Unix() {
			return false, fmt.Errorf("VerifyExpirationDate expirationDate failed")
		}
	}
	return true, nil
}

// @title    VerifyExpirationDate
// @description Verify that a credential is expired or not.
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @return    true if the VC is expired.
func VerifyExpirationDate(credential *VerifiableCredential) (bool, error) {
	issuanceDate, err := time.Parse("2006-01-02T15:04:05Z", credential.IssuanceDate)
	if err != nil {
		return false, fmt.Errorf("VerifyIssuanceDate error: %s", err)
	}
	if time.Now().UTC().Unix() < issuanceDate.Unix() {
		return false, fmt.Errorf("VerifyIssuanceDate issuanceDate failed")
	}
	return true, nil
}

// @title    VerifyProof
// @description Verify that the proof of a credential is right or not.
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @param     pk		PublicKey		    "the issuer's public key"
// @return    true if the issuer's proof is right.
func VerifyProof(credential *VerifiableCredential, pk *PublicKey) (bool, error) {
	sig, err := hex.DecodeString(credential.Proof.Hex)
	if err != nil {
		return false, fmt.Errorf("VerifyProof, hex.DecodeString signature error: %s", err)
	}
	msg, err := credential.genCredentialMsg()
	if err != nil {
		return false, fmt.Errorf("VerifyProof json marshal credential err: %s", err)
	}
	return verifyData(pk, msg, sig)
}

// @title    VerifyVC
// @description Verify a credential.
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @return    four boolean values that respectively indicate that the iusser is trusted or not, the VC is effective or not, the VC is expired or not, the issuer's proof is right or not.
func VerifyVC(credential *VerifiableCredential, TrustedIssuers []string, pk *PublicKey) (bool, bool, bool, bool, error) {
	verifyIssuer := VerifyIssuer(credential, TrustedIssuers)
	verifyIssuanceDate, err := VerifyIssuanceDate(credential)
	if err != nil {
		return false, false, false, false, err
	}
	verifyExpirationDate, err := VerifyExpirationDate(credential)
	if err != nil {
		return false, false, false, false, err
	}
	verifyProof, err := VerifyProof(credential, pk)
	if err != nil {
		return false, false, false, false, err
	}
	return verifyIssuer, verifyIssuanceDate, verifyExpirationDate, verifyProof, nil
}

func (this *VerifiableCredential) genCredentialMsg() ([]byte, error) {
	credentialData := VerifiableCredential{}
	err := copier.Copy(&credentialData, this)
	if err != nil {
		return nil, err
	}
	credentialData.Proof.Hex = ""
	msg, err := json.Marshal(credentialData)
	if err != nil {
		return nil, fmt.Errorf("genCredentialsMsg, json.Marshal error: %s", err)
	}
	return msg, nil
}
