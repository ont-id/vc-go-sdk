# Verifiable Credential Go SDK
* [Verifiable Credential Go SDK](#verifiable-credential-go-sdk)
    * [1. Overview](#1-overview)
    * [2. Credential API](#2-credential-api)
      * [2.1 Pack Credential](#21-pack-credential)
      * [2.2 Pack Credential Proof](#22-pack-credential-proof)
      * [2.3 Create VC](#23-create-vc)
      * [2.4 Verify Issuer](#24-verify-issuer)
      * [2.5 Verify Issuance Date](#25-verify-issuance-date)
      * [2.6 Verify Expiration Date](#26-verify-expiration-date)
      * [2.7 Verify Proof](#27-verify-proof)
      * [2.8 Verify VC](#28-verify-vc)
  * [3. Presentation API](#3-presentation-api)
      * [3.1 Pack Presentation](#31-pack-presentation)
      * [3.2 Pack Presentation Proof](#32-pack-presentation-proof)
      * [3.3 Create VP](#33-create-vp)
      * [3.4 Verify Presentation Proof](#34-verify-presentation-proof)
      * [3.5 Verify Presentation Creation Time](#35-verify-presentation-creation-time)


## 1. Overview
This is a comprehensive verfifable credential library written in the Go language.


## 2. Credential API

### 2.1 Pack Credential

`contexts`: [definition](https://www.w3.org/TR/vc-data-model/#contexts) [must uri](https://www.w3.org/TR/vc-data-model/#dfn-uri)

`credentialId`:[definition](https://www.w3.org/TR/vc-data-model/#identifiers) [must uri](https://www.w3.org/TR/vc-data-model/#dfn-uri)

`types`: [definition](https://www.w3.org/TR/vc-data-model/#types)

`credentialSubject`: [credentialSubject of Credential](https://www.w3.org/TR/vc-data-model/#credential-subject)

`issuerId`: [definition](https://www.w3.org/TR/vc-data-model/#issuer)

`issuanceTime`:[definition](https://www.w3.org/TR/vc-data-model/#issuance-date) [option]

`expirationDateTimestamp`: unix of expiration date timestamp

```
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

func PackCredential(contexts []string, credentialId string, types []string, credentialSubject, issuerId interface{}, credentialStatus *CredentialStatus, issuanceTime, expirationDateTimestamp int64) (*VerifiableCredential, error)


type VerifiableCredential struct {
	Context           []string          `json:"@context,omitempty"`
	Id                string            `json:"id,omitempty"`
	Type              []string          `json:"type,omitempty"`
	Issuer            interface{}       `json:"issuer,omitempty"`
	IssuanceDate      string            `json:"issuanceDate,omitempty"`
	ExpirationDate    string            `json:"expirationDate,omitempty"`
	CredentialSubject interface{}       `json:"credentialSubject,omitempty"`
	Proof             *Proof            `json:"proof,omitempty"`
	CredentialStatus  *CredentialStatus `json:"credentialStatus,omitempty"`
}

type CredentialStatus struct {
	Id   string               `json:"id"`
	Type CredentialStatusType `json:"type"`
}

type Proof struct {
	Type               string       `json:"type,omitempty"`
	Created            string       `json:"created,omitempty"`
	Challenge          string       `json:"challenge,omitempty"`
	Domain             interface{}  `json:"domain,omitempty"`
	ProofPurpose       ProofPurpose `json:"proofPurpose,omitempty"`
	VerificationMethod string       `json:"verificationMethod,omitempty"`
	Hex                string       `json:"hex,omitempty"`
	Jws                string       `json:"jws,omitempty"`
}

type ProofPurpose string

```

### 2.2 Pack Credential Proof


```
// @title    PackCredentialProof
// @description   Generate a proof from a credential without proofs. A credential can be attached the issuer's proof to form a verifiable credential.
// @param     credential	*VerifiableCredential	    "a credential need to be attached with the proof field"
// @param     created		int64			    "a unix timestamp to indicate the creation time, will use the current time if it is omitted"
// @param     proofPurpose	stirng			    "the purose of this proof"
// @param     pk		*Publickey		    "the signer's public key"
// @param     signer		crypto.PrivateKey	    "the signer's private key"
// @return    a proof that make the presentation verifiable.\

func PackCredentialProof(credential *VerifiableCredential, created int64, proofPurpose ProofPurpose, pk *PublicKey, signer crypto.PrivateKey) (*Proof, error)


```

### 2.3 Create VC

```
// @title    CreateVC
// @description   Generate a verifiable credential using a credential without the proof field and the issuer's proof that make this presentation verifiable.
// @param     credential	*VerifiableCredential	    "a credential need to be attached with the proof field"
// @param     proof		*Proof			    "the issuer's proof"
// @return    a verifiable credential

func CreateVC(credential *VerifiableCredential, proof *Proof) (*VerifiableCredential, error)

```

### 2.4 Verify Issuer


```
/ @title    VerifyIssuer
// @description Verify that a credential's issuer is in the trust list or not
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @param     TrustedIssuers	[]string		    "a list of trusted issuers, each item is a URI"
// @return    true if the issuer is trusted.

func VerifyIssuer(credential *VerifiableCredential, TrustedIssuers []string) bool


```

### 2.5 Verify Issuance Date

```
// @title    VerifyIssuanceDate
// @description Verify that a credential is effective or not.
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @return    true if the VC is  effective.
func VerifyIssuanceDate(credential *VerifiableCredential) (bool, error)

```

#### 2.6 Verify Expiration Date

```
// @title    VerifyExpirationDate
// @description Verify that a credential is expired or not.
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @return    true if the VC is expired.

func VerifyExpirationDate(credential *VerifiableCredential) (bool, error)
```

### 2.7 Verify Proof

```
// @title    VerifyProof
// @description Verify that the proof of a credential is right or not.
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @param     pk		PublicKey		    "the issuer's public key"
// @return    true if the issuer's proof is right.
func VerifyProof(credential *VerifiableCredential, pk *PublicKey) (bool, error)

```

### 2.8 Verify Vc

```
// @title    VerifyVC
// @description Verify a credential.
// @param     credential	*VerifiableCredential	    "a verifiable credential to be verified"
// @return    four boolean values that respectively indicate that the iusser is trusted or not, the VC is effective or not, the VC is expired or not, the issuer's proof is right or not.

func VerifyVC(credential *VerifiableCredential, TrustedIssuers []string, pk *PublicKey) (bool, bool, bool, bool, error)

```

## 3. Presentation API

### 3.1 Pack Presentation


```
// @title    PackPresentation
// @description Collect all the information except proofs to form a presentation without the Proof field.
// @param     credentials	 []*VerifiableCredential	"VCs to be presented"
// @param     id		    string		 "must be a URI, the identifier of new prestentation, will automatically generate a UUID if it is omitted"
// @param     contexts	   []string		"list of contexts, all of the items are URIs, can be omitted"
// @param     types		   []string		"list of types for the expression of type information, all of the items are URIs, can be omitted"
// @param     holder       interface{}	 "a URI or an Object to express the holder information, can be omitted"
// @return    a presentation without the proofs filed.
func PackPresentation(credentials []*VerifiableCredential, id string, contexts, types []string, holder interface{}) (*VerifiablePresentation, error)


type VerifiablePresentation struct {
	Context              []string                `json:"@context,omitempty"`
	Id                   string                  `json:"id,omitempty"`
	Type                 []string                `json:"type,omitempty"`
	VerifiableCredential []*VerifiableCredential `json:"verifiableCredential,omitempty"`
	Holder               interface{}             `json:"holder,omitempty"`
	Proof                []*Proof                `json:"proof,omitempty"`
}

```

### 3.2 Pack Presentation Proof


```
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

func PackPresentationProof(presentation *VerifiablePresentation, created int64, challenge string, domain interface{}, proofPurpose ProofPurpose, pk *PublicKey, signer crypto.PrivateKey) (*Proof, error)


```

### 3.3 Create VP

```
// @title CreateVP
// @description   Generate a verifiable presentation using a presentation without the proof field and a list of proofs that make this presentation verifiable.
// @param     presentation	*VerifiablePresentation	    "a presentation need to be attached with proofs"
// @param     proofs		[]*Proof		    "a list of proofs that make this presentation verifiable"
// @return    a verifiable presentation

func CreateVP(presentation *VerifiablePresentation, proofs []*Proof) (*VerifiablePresentation, error)

```

### 3.4 Verify Presentation Proof


```
// @title VerifyPresentationProof
// @description Verify that the i-th proof of a VP is valid or not
// @param     presentation	*VerifiablePresentation	    "a verifiable presentation"
// @param     index		uint32			    "the i-th proof of the VP, start from 0"
// @param     pk		PublicKey		    "the corresponding public key"
// @return    true if the i-th proof is valid

func VerifyPresentationProof(presentation *VerifiablePresentation, index uint32, pk *PublicKey) (bool, error)


```

### 3.5 Verify Presentation Creation Time

```
// @title VerifyPresentationCreationTime
// @description Verify that the i-th proof of a VP is valid or not
// @param     presentation	*VerifiablePresentation	    "a verifiable presentation"
// @param     expirationTime	int64			    "a unix timestamp that the creation time of VP must be less than it"
// @return    true if the creation time is acceptable.

func VerifyPresentationCreationTime(presentation *VerifiablePresentation, index uint32, expirationTime int64) (bool, error)

```
