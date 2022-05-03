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

// @title    PackPresentation
// @description Collect all the information except proofs to form a presentation without the Proof field.
// @param     credentials	 []*VerifiableCredential	"VCs to be presented"
// @param     id		    string		 "must be a URI, the identifier of new prestentation, will automatically generate a UUID if it is omitted"
// @param     contexts	   []string		"list of contexts, all of the items are URIs, can be omitted"
// @param     types		   []string		"list of types for the expression of type information, all of the items are URIs, can be omitted"
// @param     holder       interface{}	 "a URI or an Object to express the holder information, can be omitted"
// @return    a presentation without the proofs filed.
func PackPresentation(credentials []*VerifiableCredential, id string, contexts, types []string, holder interface{}) (*VerifiablePresentation, error) {
	if !checkUri(id) {
		return nil, fmt.Errorf("id not uri format")
	}
	presentation := new(VerifiablePresentation)
	if id == "" {
		presentation.Id = UUID_PREFIX + uuid.NewV4().String()
	} else {
		presentation.Id = id
	}
	presentation.Context = append(DefaultContext, contexts...)
	presentation.Type = append(DefaultPresentationType, types...)
	presentation.Holder = holder
	presentation.VerifiableCredential = credentials
	return presentation, nil
}

// @title    PackPresentationProof
// @description   Generate a proof from a presentation without proofs. A presentation can be attached with one or more than one proofs.
// @param     presentation	*VerifiablePresentation	    "a presentation need to be attached with proofs"
// @param     created		int64			    "a unix timestamp to indicate the creation time, will use the current time if it is omitted"
// @param     challenge		string			    "a string that protects against replay attack"
// @param     domain		string			    "a string that protects against replay attack"
// @param     proofPurpose	stirng			    "the purose of this proof"
// @param     pk		    *Publickey		    "the signer's public key"
// @param     signer		crypto.PrivateKey	    "the signer's private key"
// @return    a proof that make the presentation verifiable.
func PackPresentationProof(presentation *VerifiablePresentation, created int64, challenge string, domain interface{}, proofPurpose ProofPurpose, pk *PublicKey, signer crypto.PrivateKey) (*Proof, error) {
	proof := packProof(created, challenge, domain, proofPurpose, pk)
	presentationData := VerifiablePresentation{}
	err := copier.Copy(&presentationData, presentation)
	if err != nil {
		return nil, err
	}
	presentationData.Proof = []*Proof{proof}
	msg, err := json.Marshal(presentationData)
	if err != nil {
		return nil, fmt.Errorf("PackPresentation, json.Marshal msg error: %s", err)
	}
	sigData, err := signData(proof.Type, signer, msg)
	if err != nil {
		return nil, fmt.Errorf("PackPresentation err:%s", err)
	}
	proof.Hex = hex.EncodeToString(sigData)
	return proof, nil
}

// @title CreateVP
// @description   Generate a verifiable presentation using a presentation without the proof field and a list of proofs that make this presentation verifiable.
// @param     presentation	*VerifiablePresentation	    "a presentation need to be attached with proofs"
// @param     proofs		[]*Proof		    "a list of proofs that make this presentation verifiable"
// @return    a verifiable presentation
func CreateVP(presentation *VerifiablePresentation, proofs []*Proof) (*VerifiablePresentation, error) {
	presentation.Proof = proofs
	return presentation, nil
}

// @title VerifyPresentationProof
// @description Verify that the i-th proof of a VP is valid or not
// @param     presentation	*VerifiablePresentation	    "a verifiable presentation"
// @param     index		uint32			    "the i-th proof of the VP, start from 0"
// @param     pk		PublicKey		    "the corresponding public key"
// @return    true if the i-th proof is valid
func VerifyPresentationProof(presentation *VerifiablePresentation, index uint32, pk *PublicKey) (bool, error) {
	if index >= uint32(len(presentation.Proof)) {
		return false, fmt.Errorf("index invalid index:%d,proofs:%d", index, len(presentation.Proof))
	}
	sig, err := hex.DecodeString(presentation.Proof[index].Hex)
	if err != nil {
		return false, fmt.Errorf("VerifyPresentationProof, hex.DecodeString signature error: %s", err)
	}
	msg, err := genPresentationMsg(presentation, index)
	if err != nil {
		return false, fmt.Errorf("VerifyPresentationProof json marshal credential err: %s", err)
	}
	return verifyData(pk, msg, sig)
}

func genPresentationMsg(presentation *VerifiablePresentation, index uint32) ([]byte, error) {
	presentationData := VerifiablePresentation{}
	err := copier.Copy(&presentationData, presentation)
	proof := presentation.Proof[index]
	proof.Hex = ""
	presentationData.Proof = []*Proof{proof}
	msg, err := json.Marshal(presentationData)
	if err != nil {
		return nil, fmt.Errorf("genPresentationMsg, json.Marshal error: %s", err)
	}
	return msg, nil
}

// @title VerifyPresentationCreationTime
// @description Verify that the i-th proof of a VP is valid or not
// @param     presentation	*VerifiablePresentation	    "a verifiable presentation"
// @param     expirationTime	int64			    "a unix timestamp that the creation time of VP must be less than it"
// @return    true if the creation time is acceptable.
func VerifyPresentationCreationTime(presentation *VerifiablePresentation, index uint32, expirationTime int64) (bool, error) {
	if index+1 > uint32(len(presentation.Proof)) {
		return false, fmt.Errorf("index invalid:%d", len(presentation.Proof))
	}
	for i, proof := range presentation.Proof {
		if uint32(i) == index {
			createTime, err := time.Parse("2006-01-02T15:04:05Z", proof.Created)
			if err != nil {
				return false, fmt.Errorf("VerifyPresentationCreationTime error: %s", err)
			}
			if createTime.Unix() > expirationTime {
				return false, fmt.Errorf("VerifyPresentationCreationTime expirationDate failed")
			}
			return true, nil
		}
	}
	return false, nil
}
