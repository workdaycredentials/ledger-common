package ledger

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/mr-tron/base58"
	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

type GenerateDIDDocInput struct {
	// DID is a decentralized identifier in the format of "did:work:<id>".
	DID string
	// FullyQualifiedKeyRef is a URI that points to a public key associated with the SigningKey,
	// which can be used to verify the digital signature. This key must be included in the
	// PublicKeys map.
	FullyQualifiedKeyRef string
	// Signer is an interface can be used to digitally sign the DID Document.
	Signer proof.Signer
	// PublicKeys is a map of KeyID to Ed25519 public keys. These keys will be listed in the DID
	// Document's publicKeys field.
	PublicKeys map[string]ed25519.PublicKey
	// Issuer is an optional DID who controls the SigningKey. This is intended to be used by
	// Issuers that create a different DID Document per schema type.  Specifying the Issuer here
	// creates a linkage between the identities.
	Issuer string
	// Services are service endpoints that are published in the DID Document.
	//
	// Workday uses a "schema" service endpoint to specify which schema an identity will issue
	// credentials against. This service endpoint is not strictly necessary, but may be useful
	// for Issuers managing multiple identities.
	Services []did.ServiceDef
}

func (g GenerateDIDDocInput) validateGenerateDIDDoc() error {
	if g.DID == "" {
		return errors.New("input must have DID")
	}
	if g.FullyQualifiedKeyRef == "" {
		return errors.New("input must have fully qualified key reference")
	}
	if g.Signer == nil {
		return errors.New("input must have a signer")
	}
	if g.PublicKeys == nil || len(g.PublicKeys) == 0 {
		return errors.New("input must have at least one public key")
	}
	return nil
}

// TODO(gabe): on JCS uptake change "type" to "signer"
// GenerateLedgerDIDDoc generates DID Document based on the current state of the input.
func (g GenerateDIDDocInput) GenerateLedgerDIDDoc() (*DIDDoc, error) {
	if err := g.validateGenerateDIDDoc(); err != nil {
		return nil, err
	}
	var didPubKeys []did.KeyDef
	if g.Issuer == "" {
		g.Issuer = g.DID
	}
	for k, v := range g.PublicKeys {
		keyEntry := did.KeyDef{
			ID:              g.DID + "#" + k,
			Type:            proof.GetCorrespondingKeyType(g.Signer.Type()),
			Controller:      g.Issuer,
			PublicKeyBase58: base58.Encode(v),
		}
		didPubKeys = append(didPubKeys, keyEntry)
	}

	doc := did.UnsignedDIDDoc{
		ID:        g.DID,
		PublicKey: didPubKeys,
		Service:   g.Services,
	}
	signedDoc, err := did.SignDIDDocGeneric(g.Signer, doc, g.FullyQualifiedKeyRef)
	if err != nil {
		logrus.WithError(err).Error("could not sign did doc")
		return nil, err
	}

	ledgerDoc := DIDDoc{
		Metadata: &Metadata{
			Type:         util.DIDDocTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           signedDoc.ID,
			Author:       signedDoc.PublicKey[0].Controller,
			Authored:     time.Now().UTC().Format(time.RFC3339),
		},
		DIDDoc: signedDoc,
	}
	if err := SignLedgerDocGeneric(g.Signer, &ledgerDoc, g.FullyQualifiedKeyRef); err != nil {
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
	signingKeyRef := id + "#" + did.InitialKey
	pubKeys := make(map[string]ed25519.PublicKey)
	pubKeys[did.InitialKey] = pubKey

	didDoc, err := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: signingKeyRef,
		Signer:               proof.WorkEd25519Signer{PrivKey: seedKey},
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
func GenerateKeyDIDDoc(publicKey ed25519.PublicKey, keyref string) *did.UnsignedDIDDoc {
	id := did.GenerateDIDKey(publicKey)
	publicKeyDefs := []did.KeyDef{
		{
			ID:              id + "#" + keyref,
			Type:            proof.WorkEdKeyType,
			Controller:      id,
			PublicKeyBase58: base58.Encode(publicKey),
		},
	}
	return &did.UnsignedDIDDoc{
		ID:        id,
		PublicKey: publicKeyDefs,
		Service:   nil,
	}
}
