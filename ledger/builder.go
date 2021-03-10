package ledger

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"golang.org/x/crypto/ed25519"
	"gopkg.in/go-playground/validator.v9"

	"github.com/mr-tron/base58"
	"github.com/sirupsen/logrus"

	"go.wday.io/credentials-open-source/ledger-common/did"
	"go.wday.io/credentials-open-source/ledger-common/proof"
	"go.wday.io/credentials-open-source/ledger-common/util"
)

type GenerateDIDDocInput struct {
	// DID is a decentralized identifier in the format of "did:work:<id>".
	DID did.DID `validate:"required"`
	// FullyQualifiedKeyRef is a URI that points to a public key associated with the SigningKey,
	// which can be used to verify the digital signature. This key must be included in the
	// PublicKeys map.
	FullyQualifiedKeyRef string `validate:"required"`
	// Signer is an interface can be used to digitally sign the DID Document.
	Signer proof.Signer `validate:"required"`
	// SignatureType specifies the suite used to generate the DID Doc signature
	SignatureType proof.SignatureType `validate:"required"`
	// PublicKeys is a map of KeyID to Ed25519 public keys. These keys will be listed in the DID
	// Document's publicKeys field.
	PublicKeys map[string]ed25519.PublicKey `validate:"required"`
	// Issuer is an optional DID who controls the SigningKey. This is intended to be used by
	// Issuers that create a different DID Document per schema type.  Specifying the Issuer here
	// creates a linkage between the identities.
	Issuer did.DID `validate:"required"`
	// Services are service endpoints that are published in the DID Document.
	//
	// Workday uses a "schema" service endpoint to specify which schema an identity will issue
	// credentials against. This service endpoint is not strictly necessary, but may be useful
	// for Issuers managing multiple identities.
	Services []did.ServiceDef
}

// GenerateLedgerDIDDoc generates DID Document based on the current state of the input.
func (g GenerateDIDDocInput) GenerateLedgerDIDDoc() (*DIDDoc, error) {
	if err := validator.New().Struct(g); err != nil {
		return nil, err
	}

	var didPubKeys []did.KeyDef
	if g.Issuer == "" {
		g.Issuer = g.DID
	}
	for k, v := range g.PublicKeys {
		keyEntry := did.KeyDef{
			ID:              did.GenerateKeyID(g.DID, k),
			Type:            g.Signer.Type(),
			Controller:      g.Issuer,
			PublicKeyBase58: base58.Encode(v),
		}
		didPubKeys = append(didPubKeys, keyEntry)
	}

	doc := did.DIDDoc{
		ID:        g.DID,
		PublicKey: didPubKeys,
		Service:   g.Services,
	}

	proofVersion := proof.V2
	if g.SignatureType == proof.EcdsaSecp256k1SignatureType {
		proofVersion = proof.V1
	}
	suite, err := proof.SignatureSuites().GetSuite(g.SignatureType, proofVersion)
	if err != nil {
		return nil, err
	}
	if err = suite.Sign(&doc, g.Signer, nil); err != nil {
		logrus.WithError(err).Error("could not sign did doc")
		return nil, err
	}

	ledgerDoc := DIDDoc{
		Metadata: &Metadata{
			Type:         util.DIDDocTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           doc.ID.String(),
			Author:       doc.PublicKey[0].Controller,
			Authored:     time.Now().UTC().Format(time.RFC3339),
		},
		DIDDoc: &doc,
	}
	if err = suite.Sign(&ledgerDoc, g.Signer, nil); err != nil {
		logrus.WithError(err).Error("could not sign ledger did doc")
		return nil, err
	}
	return &ledgerDoc, nil
}

// GenerateB64EncodedEd25519DIDDoc creates a DIDDoc from a base64 encoded ed25519 PrivateKey.
func GenerateB64EncodedEd25519DIDDoc(b64EncodedPrivKey string) (string, error) {
	b64Encoding := base64.StdEncoding
	decodeKeyBytes, err := b64Encoding.DecodeString(b64EncodedPrivKey)
	if err != nil {
		return "", err
	}
	seedKey := ed25519.PrivateKey(decodeKeyBytes)
	pubKey := seedKey.Public().(ed25519.PublicKey)

	id := did.GenerateDID(pubKey)
	signingKeyRef := did.GenerateKeyID(id, did.InitialKey)
	pubKeys := make(map[string]ed25519.PublicKey)
	pubKeys[did.InitialKey] = pubKey

	signer, err := proof.NewEd25519Signer(seedKey, signingKeyRef)
	if err != nil {
		return "", err
	}
	didDoc, err := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: signingKeyRef,
		Signer:               signer,
		SignatureType:        proof.JCSEdSignatureType,
		PublicKeys:           pubKeys,
		Issuer:               id,
	}.GenerateLedgerDIDDoc()
	if err != nil {
		return "", err
	}
	jsonBytes, err := json.Marshal(didDoc)
	return b64Encoding.EncodeToString(jsonBytes), err
}

// GenerateKeyDIDDoc generates DID Document as defined by The did:key Method based on supplied ED25519 Public Key
// and keyref.
func GenerateKeyDIDDoc(publicKey ed25519.PublicKey, keyRef string) *did.DIDDoc {
	id := did.GenerateDIDKey(publicKey)
	publicKeyDefs := []did.KeyDef{
		{
			ID:              did.GenerateKeyID(id, keyRef),
			Type:            proof.Ed25519KeyType,
			Controller:      id,
			PublicKeyBase58: base58.Encode(publicKey),
		},
	}
	return &did.DIDDoc{
		ID:        id,
		PublicKey: publicKeyDefs,
		Service:   nil,
	}
}
