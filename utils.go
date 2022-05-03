package vc_go_sdk

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"time"

	"github.com/ontio/ontology-crypto/keypair"

	s "github.com/ontio/ontology-crypto/signature"
)

func checkUri(raw string) bool {
	if raw == "" {
		return true
	}
	_, err := url.ParseRequestURI(raw)
	if err != nil {
		return false
	}
	return true
}

func checkIssuerVaild(issuer interface{}) bool {
	t := reflect.TypeOf(issuer).Kind()
	if t != reflect.Struct && t != reflect.String {
		return false
	}
	if t == reflect.String {
		return checkUri(issuer.(string))
	} else if t == reflect.Struct {
		b, err := json.Marshal(issuer)
		if err != nil {
			return false
		}
		m := make(map[string]interface{})
		if err := json.Unmarshal(b, &m); err == nil {
			return false
		}
		if v, present := m["id"]; present {
			t := reflect.TypeOf(v).Kind()
			if t != reflect.String {
				return false
			}
			return checkUri(t.String())
		} else {
			return false
		}
	}
	return true
}

func checkCredentialSubject(credentialSubject interface{}) bool {
	t := reflect.TypeOf(credentialSubject).Kind()
	if t != reflect.Struct && t != reflect.Slice {
		return false
	}
	if t == reflect.Slice {
		s := reflect.ValueOf(t)
		for i := 0; i < s.Len(); i++ {
			return checkStructUri(s.Index(i))
		}
	} else if t == reflect.Struct {
		return checkStructUri(credentialSubject)
	}
	return false
}

func checkStructUri(credentialSubject interface{}) bool {
	t := reflect.TypeOf(credentialSubject).Kind()
	if t != reflect.Struct {
		return false
	}
	b, err := json.Marshal(credentialSubject)
	if err != nil {
		return false
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m); err != nil {
		return false
	}
	if v, present := m["id"]; present {
		t := reflect.TypeOf(v).Kind()
		if t != reflect.String {
			return false
		}
		return checkUri(v.(string))
	} else {
		return false
	}
}

func signData(signType string, signer crypto.PrivateKey, data []byte) ([]byte, error) {
	SignatureScheme, err := s.GetScheme(signType)
	if err != nil {
		return nil, fmt.Errorf("signData GetScheme err:%s", err)
	}
	sig, err := s.Sign(SignatureScheme, signer, data, nil)
	if err != nil {
		return nil, fmt.Errorf("signData Sign error: %s", err)
	}
	sigData, err := s.Serialize(sig)
	if err != nil {
		return nil, fmt.Errorf("signData Serialize error: %s", err)
	}
	return sigData, nil
}

func verifyData(pk *PublicKey, msg, signData []byte) (bool, error) {
	sig, err := s.Deserialize(signData)
	if err != nil {
		return false, err
	}
	pub, err := hex.DecodeString(pk.PublicKeyHex)
	if err != nil {
		return false, err
	}
	pubkey, err := keypair.DeserializePublicKey(pub)
	if err != nil {
		return false, err
	}
	return s.Verify(pubkey, msg, sig), nil
}

func packProof(created int64, challenge string, domain interface{}, proofPurpose ProofPurpose, pk *PublicKey) *Proof {
	createdTime := time.Unix(created, 0).UTC().Format("2006-01-02T15:04:05Z")
	return &Proof{
		Type:               pk.Type,
		Created:            createdTime,
		Challenge:          challenge,
		Domain:             domain,
		ProofPurpose:       proofPurpose,
		VerificationMethod: pk.Id,
	}
}
