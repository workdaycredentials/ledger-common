package did

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"

	"go.wday.io/credentials-open-source/ledger-common/proof"
	"go.wday.io/credentials-open-source/ledger-common/util"
)

const (
	// AdminDIDKey the key for ledger value of admin did
	AdminDIDKey = "admin_did"

	// InitialKey the key reference assigned to the first key in a DID Doc
	InitialKey    = "key-1"
	WorkDIDMethod = "did:work:"
	KeyDIDMethod  = "did:key:"

	// Codec for Ed25519 multi-format
	// https://github.com/multiformats/multicodec
	Ed25519Codec byte = 0xed

	// SchemaContext is the JSON-LD @context value that points to the W3C DID v1 context.
	// Workday has chosen not to use JSON-LD for DID Documents.
	//
	// Deprecated: This field is kept for historical purposes only. New documents should exclude it.
	SchemaContext = "https://w3id.org/did/v1"
)

// ExtractDIDFromKeyRef parses a key reference in the form of DID#keyID and returns the DID.
// If the key reference doesn't contain a hash "#" symbol, the entire key reference is returned.
func ExtractDIDFromKeyRef(keyRef string) DID {
	s := strings.SplitN(keyRef, "#", 2)
	return DID(s[0])
}

// GenerateDID generates a Decentralized ID in the form of "did:work:<id>" based on an Ed25519
// public key. Workday's DID method uses the first 16 bytes of the public key as a unique random
// value, assuming that the caller generates a new random key pair when creating a new ID.
func GenerateDID(publicKey ed25519.PublicKey) DID {
	return DID(WorkDIDMethod + base58.Encode(publicKey[0:16]))
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

// GenerateDIDFromB64PubKey converts a base64 encoded Ed25519 public key into a Decentralized ID.
// See GenerateDID.
func GenerateDIDFromB64PubKey(edBase64PubKey string) (DID, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(edBase64PubKey)
	if err != nil {
		return "", errors.Wrap(err, "unable to base64 decode ED key")
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)
	return GenerateDID(pubKey), nil
}

// GetProofCreatorKeyDef returns the Key Definition that can be used to verify the Proof on the
// given DID Document.  This assumes that DID Documents are self-signed, which is always the case
// in Workday. Returns an error if the public key is not found.
func GetProofCreatorKeyDef(didDoc DIDDoc) (*KeyDef, error) {
	var publicKey KeyDef
	for _, keyDef := range didDoc.PublicKey {
		if keyDef.ID == didDoc.Proof.GetVerificationMethod() {
			publicKey = keyDef
		}
	}
	if publicKey.PublicKeyBase58 == "" {
		return nil, errors.New("could not find public key")
	}

	return &publicKey, nil
}

// GenerateDIDKey generates a non-registry based Decentralized DID in the form of "did:key:<id>" based on an Ed25519
// public key. The DID Key Method expands a cryptographic public key into a DID Document.
// Note: As of May 2020, the DID Key method is still in unofficial draft (https://w3c-ccg.github.io/did-method-key)
func GenerateDIDKey(publicKey ed25519.PublicKey) DID {
	pk := append([]byte{Ed25519Codec}, publicKey...)
	return DID(KeyDIDMethod + "z" + base58.Encode(pk))
}

// GenerateDIDKeyFromB64PubKey converts a base64 encoded Ed25519 public key into a DID Key.
// See GenerateDIDKey.
func GenerateDIDKeyFromB64PubKey(edBase64PubKey string) (did DID, err error) {
	decodedPubKey, err := base64.StdEncoding.DecodeString(edBase64PubKey)
	if err != nil {
		return
	}
	return GenerateDIDKey(decodedPubKey), nil
}

// ExtractEdPublicKeyFromDID extracts an Ed25519 Public Key from a DID Key.
func ExtractEdPublicKeyFromDID(did DID) (key ed25519.PublicKey, err error) {
	prefix := KeyDIDMethod + "z"
	if !strings.HasPrefix(did.String(), prefix) {
		err = fmt.Errorf("DID<%s> format not supported", did)
		return
	}
	decodedKey, err := base58.Decode(did[len(prefix):].String())
	if err != nil {
		return nil, errors.New("cannot decode DID")
	}

	codec := decodedKey[0]
	if codec == Ed25519Codec {
		return decodedKey[1:], nil
	}
	err = fmt.Errorf("key cannot be extracted from DID<%s>", did)
	return
}

// DeactivateDIDDoc creates a deactivated DID Document.
// Returns an error if the Signer fails to generate the digital signature.
// Uses the same signature type as is on the provided DID Doc
func DeactivateDIDDoc(doc DIDDoc, key ed25519.PrivateKey) (*DIDDoc, error) {
	signer, err := proof.NewEd25519Signer(key, doc.PublicKey[0].ID)
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

// AddKeyToDIDDoc takes a DID Doc, a key to add, and a signing key and its reference. The signing key must match the key
// that the current DID Doc is signed with, this is used to update the proof on the document and authenticate
// the update action. The check is based on the deterministic generation of the DID, which is only applicable for
// did:work DIDs. Conflict checking is done on the key reference.
func AddKeyToDIDDoc(doc DIDDoc, keyToAdd KeyDef, signingKey ed25519.PrivateKey, signingKeyRef string) (*DIDDoc, error) {
	// validate before updating the doc
	if keyToAdd.IsEmpty() {
		return nil, errors.New("cannot add empty key def")
	}
	if !strings.HasPrefix(doc.ID.String(), WorkDIDMethod) {
		return nil, errors.New("cannot add to non-did:work document")
	}
	// make sure the signing key matches the one used for the signature FIXME: it's a ref, not a DID
	if !strings.Contains(doc.Proof.GetVerificationMethod(), GenerateDID(signingKey.Public().(ed25519.PublicKey)).String()) {
		return nil, errors.New("signing key not found in DID Document")
	}
	// map of key id to index in document
	kids := make(map[string]int)
	for i, kid := range doc.PublicKey {
		kids[kid.ID] = i
	}
	// make sure the kid to add is unique
	newKID := keyToAdd.ID
	if _, ok := kids[keyToAdd.ID]; ok {
		return nil, fmt.Errorf("key id<%s> already present in DID Doc", newKID)
	}
	// resolve the signing key
	if _, ok := kids[signingKeyRef]; !ok {
		return nil, fmt.Errorf("key id<%s> is not present in DID Doc", signingKeyRef)
	}

	// update the doc
	doc.PublicKey = append(doc.PublicKey, keyToAdd)

	// sign using the same key and signing method as the present document
	signer, err := proof.NewEd25519Signer(signingKey, signingKeyRef)
	if err != nil {
		return nil, err
	}
	suite, err := proof.SignatureSuites().GetSuiteForProof(doc.Proof)
	if err != nil {
		return nil, err
	}
	doc.SetProof(nil)
	err = suite.Sign(&doc, signer, nil)
	return &doc, err
}
