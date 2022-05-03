package vc_go_sdk

const (
	PROOF_PURPOSE ProofPurpose = "assertionMethod"
	UUID_PREFIX                = "urn:uuid:"
)

type CredentialStatusType string
type ProofPurpose string

var DefaultPresentationType = []string{"VerifiablePresentation"}

var DefaultContext = []string{"https://www.w3.org/2018/credentials/v1", "https://ontid.ont.io/credentials/v1"}
var DefaultCredentialType = []string{"VerifiableCredential"}

var JWTSignType = map[string]string{
	"EcdsaSecp224r1VerificationKey2019": "ES224",
	"EcdsaSecp256r1VerificationKey2019": "ES256",
	"EcdsaSecp384r1VerificationKey2019": "ES384",
	"EcdsaSecp521r1VerificationKey2019": "ES512",
	"EcdsaSecp256k1VerificationKey2019": "ES256K",
	"Ed25519VerificationKey2018":        "EdDSA",
	"SM2VerificationKey2019":            "SM",
}

var JsonSignType = map[string]string{
	"ES224":  "EcdsaSecp224r1VerificationKey2019",
	"ES256":  "EcdsaSecp256r1VerificationKey2019",
	"ES384":  "EcdsaSecp384r1VerificationKey2019",
	"ES512":  "EcdsaSecp521r1VerificationKey2019",
	"ES256K": "EcdsaSecp256k1VerificationKey2019",
	"EdDSA":  "Ed25519VerificationKey2018",
	"SM":     "SM2VerificationKey2019",
}

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

type PublicKey struct {
	Id           string `json:"id"`
	Type         string `json:"type"`
	PublicKeyHex string `json:"publicKeyHex"`
}

type PublicKeyList []*PublicKey

type VerifiablePresentation struct {
	Context              []string                `json:"@context,omitempty"`
	Id                   string                  `json:"id,omitempty"`
	Type                 []string                `json:"type,omitempty"`
	VerifiableCredential []*VerifiableCredential `json:"verifiableCredential,omitempty"`
	Holder               interface{}             `json:"holder,omitempty"`
	Proof                []*Proof                `json:"proof,omitempty"`
}
