package credential

import (
	"context"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gopkg.in/go-playground/validator.v9"

	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

// Builder is used to construct signed Verifiable Credential.
type Builder struct {
	// SubjectDID is the Decentralized ID of the subject of the credential, who is normally also the
	// credential Holder. This is recorded as the "id" (JSON-LD "@id") property in the
	// credentialSubject block of the credential.
	SubjectDID string `validate:"required"`
	// Data is a map of claims that adhere to the schema referenced in the Metadata.
	Data map[string]interface{}
	// Metadata is information about the credential.
	Metadata *Metadata `validate:"required"`
	// KeyRef is the URI of the public key that can be used to verify the proof signature.
	KeyRef string `validate:"required"`
	// Signer has the ability to generate a digital signature using a private key associated to
	// the KeyRef public key.
	Signer proof.Signer `validate:"required"`
}

// BuildCredential returns a signed Verifiable Credential using the current state of the builder.
func (b Builder) BuildCredential(ctx context.Context) (*VerifiableCredential, error) {
	// validate all required fields are set
	if err := validator.New().StructCtx(ctx, b); err != nil {
		return nil, err
	}

	// first, set the subject "id" claim
	credSubjects := map[string]interface{}{
		SubjectIDAttribute: b.SubjectDID,
	}

	var err error
	var p *proof.Proof
	switch b.Signer.Type() {
	case proof.JCSEdSignatureType:
		credential := VerifiableCredential{
			UnsignedVerifiableCredential: UnsignedVerifiableCredential{
				Metadata:          *b.Metadata,
				CredentialSubject: credSubjects,
			},
		}
		p, err = proof.CreateJCSEd25519Proof(&credential, b.Signer, b.KeyRef)
		if err != nil {
			return nil, err
		}

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		encodedID, err := EncodeAttributeClaimDataForSigning(*b.Metadata, SubjectIDAttribute, b.SubjectDID)
		if err != nil {
			return nil, err
		}
		p, err = proof.CreateWorkEd25519ProofGeneric(b.Signer, encodedID, b.KeyRef, uuid.New().String(), false)
		if err != nil {
			return nil, err
		}
	}

	claimProofs := map[string]proof.Proof{
		SubjectIDAttribute: *p,
	}

	// then, add claim for each data attribute
	for attribute, value := range b.Data {
		credSubjects[attribute] = value

		var err error
		var claimProof *proof.Proof
		switch b.Signer.Type() {
		case proof.JCSEdSignatureType:
			credential := VerifiableCredential{
				UnsignedVerifiableCredential: UnsignedVerifiableCredential{
					Metadata:          *b.Metadata,
					CredentialSubject: map[string]interface{}{attribute: value},
				},
			}
			claimProof, err = proof.CreateJCSEd25519Proof(&credential, b.Signer, b.KeyRef)
			if err != nil {
				return nil, err
			}

		case proof.Ed25519SignatureType:
			fallthrough

		case proof.WorkEdSignatureType:
			encoding, err := EncodeAttributeClaimDataForSigning(*b.Metadata, attribute, value)
			if err != nil {
				logrus.WithError(err).Error("problem encoding credential claims")
				// should accumulate errors?
				return nil, err
			}
			claimProof, err = proof.CreateWorkEd25519ProofGeneric(b.Signer, encoding, b.KeyRef, uuid.New().String(), false)
			if err != nil {
				return nil, err
			}
		}
		claimProofs[attribute] = *claimProof
	}

	unsignedCred := UnsignedVerifiableCredential{
		Metadata:          *b.Metadata,
		CredentialSubject: credSubjects,
		ClaimProofs:       claimProofs,
	}

	var credProof *proof.Proof
	switch b.Signer.Type() {
	case proof.JCSEdSignatureType:
		cred := VerifiableCredential{
			UnsignedVerifiableCredential: unsignedCred,
		}
		credProof, err = proof.CreateJCSEd25519Proof(&cred, b.Signer, b.KeyRef)
		if err != nil {
			return nil, err
		}

	case proof.Ed25519SignatureType:
		fallthrough

	case proof.WorkEdSignatureType:
		credJSON, err := canonical.Marshal(unsignedCred)
		if err != nil {
			return nil, err
		}

		credProof, err = proof.CreateWorkEd25519ProofGeneric(b.Signer, []byte(base64.StdEncoding.EncodeToString(credJSON)), b.KeyRef, uuid.New().String(), false)
		if err != nil {
			return nil, err
		}
	}
	return &VerifiableCredential{
		UnsignedVerifiableCredential: unsignedCred,
		Proof:                        credProof,
	}, nil
}
