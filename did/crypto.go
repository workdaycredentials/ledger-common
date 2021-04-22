package did

import (
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

const (
	// AdminDIDKey the key for ledger value of admin did
	AdminDIDKey = "admin_did"

	// InitialKey the key reference assigned to the first key in a DID Doc
	InitialKey = "key-1"

	IONDIDMethod = "did:ion:"

	// SchemaContext is the JSON-LD @context value that points to the W3C DID v1 context.
	// Workday has chosen not to use JSON-LD for DID Documents.
	// Deprecated: This field is kept for historical purposes only. New documents should exclude it.
	SchemaContext = "https://w3id.org/did/v1"
)

// ExtractDIDFromKeyRef parses a key reference in the form of DID#keyID and returns the DID.
// If the key reference doesn't contain a hash "#" symbol, the entire key reference is returned.
func ExtractDIDFromKeyRef(keyRef string) DID {
	s := strings.SplitN(keyRef, "#", 2)
	return DID(s[0])
}

// TODO consider making keyref a type
// type KeyRef string
//
// func (k *KeyRef) GetDID() string {
// 	s := strings.Split(keyRef, "#")
// 	return s[0]		return s[0]
// }
//
// func (k *KeyRef) GetID() string {
// 	s := strings.Split(keyRef, "#")
// 	return s[1]		return s[1]
// }

// GenerateKeyID builds a fully qualified key reference given a DID and a key fragment
func GenerateKeyID(did DID, fragment string) string {
	return fmt.Sprintf("%s#%s", did, fragment)
}

// GetProofCreatorKeyDef returns the Key Definition that can be used to verify the Proof on the
// given DID Document.  This assumes that DID Documents are self-signed, which is always the case
// in Workday. Returns an error if the public key is not found.
func GetProofCreatorKeyDef(didDoc DIDDoc) (*KeyDef, error) {
	var publicKey KeyDef
	for _, keyDef := range didDoc.GetVerificationMethod() {
		if keyDef.ID == didDoc.Proof.GetVerificationMethod() {
			publicKey = keyDef
		}
	}
	if publicKey.PublicKeyBase58 == "" {
		return nil, errors.New("could not find public key")
	}

	return &publicKey, nil
}

// DeactivateDIDDoc creates a deactivated DID Document.
// Returns an error if the Signer fails to generate the digital signature.
// Uses the same signature type as is on the provided DID Doc
func DeactivateDIDDoc(doc DIDDoc, key ed25519.PrivateKey) (*DIDDoc, error) {
	publicKey := doc.GetVerificationMethod()[0]
	signer, err := proof.NewEd25519Signer(key, publicKey.ID)
	if err != nil {
		return nil, err
	}
	return DeactivateDIDDocGeneric(signer, doc.Proof.Type, doc.ID)
}

// DeactivateDIDDocGeneric creates a deactivated DID Document.
// Returns an error if the Signer fails to generate the digital signature.
func DeactivateDIDDocGeneric(signer proof.Signer, signatureType proof.SignatureType, did DID) (*DIDDoc, error) {
	doc := DIDDoc{ID: did}
	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	if err != nil {
		return nil, err
	}
	err = suite.Sign(&doc, signer, nil)
	return &doc, err
}

// AsVerifier builds a verifier given a key definition that can be used to verify
// signed objects by the key in the definition
func AsVerifier(keyDef KeyDef) (proof.Verifier, error) {
	keyType := keyDef.Type
	switch keyType {
	case proof.EcdsaSecp256k1KeyType:
		pubKey, err := util.ExtractPublicKeyFromBase58Der(keyDef.PublicKeyBase58)
		if err != nil {
			return nil, err
		}
		return &proof.Secp256K1Verifier{PublicKey: pubKey}, nil
	case proof.WorkEdKeyType:
		fallthrough
	case proof.Ed25519KeyType:
		pubKey, err := base58.Decode(keyDef.PublicKeyBase58)
		if err != nil {
			return nil, err
		}
		return &proof.Ed25519Verifier{PubKey: pubKey}, nil
	}
	return nil, fmt.Errorf("unknown key type: %s", keyType)
}
