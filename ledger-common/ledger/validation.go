package ledger

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"

	"github.com/mr-tron/base58"
	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

// DID //

func (d DIDDoc) Validate(ctx context.Context, provider DIDDocProvider) error {
	if err := d.ValidateStatic(); err != nil {
		logrus.Errorf("Could not statically validate did doc: %+v", d)
		return err
	}

	if err := d.ValidateUniqueness(ctx, provider); err != nil {
		logrus.Errorf("Could not validate did doc uniqueness: %s", d.ID)
		return err
	}
	return nil
}

func (d DIDDoc) ValidateStatic() error {
	if err := d.ValidateNotEmpty(); err != nil {
		logrus.WithError(err).Error()
		return err
	}

	if err := ValidateDID(d.ID); err != nil {
		logrus.Errorf("Could not validate did doc did: %s", d.ID)
		return err
	}

	if err := d.ValidateMetadata(); err != nil {
		logrus.Errorf("Could not validate did doc metadata: %s", d.ID)
		return err
	}

	if err := d.ValidateProof(); err != nil {
		logrus.Errorf("Could not validate did doc proof: %s", d.ID)
		return err
	}
	return nil
}

func (d *DIDDoc) ValidateNotEmpty() error {
	if d.IsEmpty() || d.DIDDoc.IsEmpty() {
		return errors.New("did doc empty or nil")
	}
	return nil
}

func (d DIDDoc) ValidateDeactivated() error {
	if err := d.ValidateNotEmpty(); err != nil {
		return err
	}

	if err := ValidateDID(d.DIDDoc.ID); err != nil {
		return err
	}

	if len(d.DIDDoc.PublicKey) > 0 {
		return fmt.Errorf("deactivated DID Doc cannot contain public keys")
	}

	if len(d.DIDDoc.Authentication) > 0 {
		return fmt.Errorf("deactivated DID Doc cannot contain authentication keys")
	}

	if len(d.DIDDoc.Service) > 0 {
		return fmt.Errorf("deactivated DID Doc cannot contain services")
	}

	return nil
}

func ValidateDID(did string) error {
	// The DID is generated as a base58 encoding of the lower 16 bytes of the public key
	// and can be variable length, probably between 22-25 characters. For now we can say
	// that it's at least 16 characters.
	// TODO In the future we should base58 decode and ensure that the length is 16 bytes.
	isValid, err := regexp.MatchString(`^did:work:\w{16}`, did)
	if err != nil {
		return err
	}
	if !isValid {
		return fmt.Errorf("invalid DID")
	}
	return nil
}

func (d DIDDoc) ValidateMetadata() error {
	if d.Metadata.IsEmpty() {
		return errors.New("metadata on did doc is empty")
	}
	if d.Type != util.DIDDocTypeReference_v1_0 {
		return fmt.Errorf("invalid type %s", d.Type)
	}
	if d.ModelVersion != util.Version_1_0 {
		return fmt.Errorf("invalid modelVersion %s", d.ModelVersion)
	}
	return nil
}

func (d DIDDoc) ValidateProof() error {
	keyDef, err := did.GetProofCreatorKeyDef(*d.DIDDoc)
	if err != nil {
		return err
	}

	if keyDef.Type == proof.EcdsaSecp256k1KeyType {
		verifier, err := did.AsVerifier(*keyDef)
		if err != nil {
			return err
		}
		suite, err := proof.SignatureSuites().GetSuiteForProof(d.GetProof())
		if err != nil {
			return err
		}
		return suite.Verify(&d, verifier)
	}

	decodedPublicKey, err := base58.Decode(keyDef.PublicKeyBase58)
	if err != nil {
		return err
	}
	verifier := &proof.Ed25519Verifier{PubKey: decodedPublicKey}
	suite, err := proof.SignatureSuites().GetSuiteForProof(d.GetProof())
	if err != nil {
		return err
	}
	if err := suite.Verify(&d, verifier); err != nil {
		return err
	}
	return suite.Verify(d.DIDDoc, verifier)
}

func (d DIDDoc) ValidateUniqueness(ctx context.Context, provider DIDDocProvider) error {
	record, err := provider(ctx, d.ID)
	if err != nil {
		logrus.WithError(err).Errorf("failure to lookup DID Record: %s", d.ID)
		return nil
	}
	if record != nil && record.ID != "" && !reflect.DeepEqual(d, *record) {
		return fmt.Errorf("DID Doc already exists: %s", d.ID)
	}
	return nil
}

// Revocation //
func ValidateRevocations(ctx context.Context, revocations []Revocation, provider Provider) error {
	for _, r := range revocations {
		if err := r.Validate(ctx, provider); err != nil {
			logrus.WithError(err).Errorf("Could not validate revocation: %s", r.UnsignedRevocation.ID)
			return err
		}
	}
	return nil
}

func (r Revocation) Validate(ctx context.Context, provider Provider) error {
	if err := r.ValidateStatic(); err != nil {
		logrus.WithError(err).Errorf("Could not statically validate revocation: %+v", r)
		return err
	}

	if err := r.ValidateProof(ctx, provider.DIDDocProvider); err != nil {
		logrus.Errorf("Could not validate revocation proof: %s", r.UnsignedRevocation.ID)
		return err
	}

	if err := r.ValidateUniqueness(ctx, provider.RevocationProvider); err != nil {
		logrus.Errorf("Could not validate revocation uniqueness: %s", r.UnsignedRevocation.ID)
		return err
	}
	return nil
}

func (r Revocation) ValidateStatic() error {
	if err := r.ValidateNotEmpty(); err != nil {
		logrus.WithError(err).Error()
		return err
	}

	if err := r.ValidateKey(); err != nil {
		logrus.WithError(err).Error("unexpected revocation key error")
		return err
	}

	if err := r.ValidateMetadata(); err != nil {
		logrus.Errorf("Could not validate schema metadata: %s", r.UnsignedRevocation.ID)
		return err
	}
	return nil
}

func (r Revocation) ValidateNotEmpty() error {
	if r.IsEmpty() || r.UnsignedRevocation.IsEmpty() {
		return errors.New("revocation empty or nil")
	}
	return nil
}

func (r Revocation) ValidateKey() error {
	expectedRevocationID := GenerateRevocationKey(r.IssuerDID, r.CredentialID)
	if r.UnsignedRevocation.ID != expectedRevocationID {
		keyErr := fmt.Errorf("revocation id '%s' for credential '%s' and cred def did '%s', expected '%s'", r.UnsignedRevocation.ID, r.CredentialID, r.IssuerDID, expectedRevocationID)
		return keyErr
	}
	return nil
}

func (r Revocation) ValidateMetadata() error {
	if r.Type != util.RevocationTypeReference_v1_0 {
		return fmt.Errorf("invalid type %s", r.Type)
	}
	if r.ModelVersion != util.Version_1_0 {
		return fmt.Errorf("invalid modelVersion %s", r.ModelVersion)
	}
	return nil
}

func (r Revocation) ValidateProof(ctx context.Context, provider DIDDocProvider) error {
	keyDef, err := GetKeyDef(ctx, r.IssuerDID, r.Proof.GetVerificationMethod(), provider)
	switch {
	case err != nil:
		logrus.WithError(err).Error("could not get key def")
		return err
	case keyDef == nil:
		return fmt.Errorf("could not resolve specified key '%s' in did doc '%s'", r.Proof.GetVerificationMethod(), r.IssuerDID)
	}

	key, err := keyDef.GetDecodedPublicKey()
	if err != nil {
		return err
	}
	verifier := &proof.Ed25519Verifier{PubKey: key}
	suite, err := proof.SignatureSuites().GetSuiteForProof(r.GetProof())
	if err != nil {
		return err
	}
	return suite.Verify(r, verifier)
}

func (r Revocation) ValidateUniqueness(ctx context.Context, provider RevocationProvider) error {
	record, err := provider(ctx, r.UnsignedRevocation.CredentialID, r.UnsignedRevocation.ID)
	if err != nil {
		logrus.WithError(err).Errorf("failure to lookup revocation: %s", r.UnsignedRevocation.ID)
		return nil
	}
	if record != nil && record.UnsignedRevocation.ID != "" && !reflect.DeepEqual(r, *record) {
		return fmt.Errorf("revocation already exists: %s", r.UnsignedRevocation.ID)
	}
	return nil
}

// Schema //

const (
	IDRxStr = "^did:work:\\S+\\;id=\\S+;version=\\d+\\.\\d+$"
)

func (s Schema) Validate(ctx context.Context, provider Provider) error {
	if err := s.ValidateStatic(); err != nil {
		logrus.Errorf("Could not statically validate schema: %+v", s)
		return err
	}

	if err := s.ValidateProof(ctx, provider.DIDDocProvider); err != nil {
		logrus.Errorf("Could not validate schema proof: %s", s.ID)
		return err
	}

	if err := s.ValidateUniqueness(ctx, provider.SchemaProvider); err != nil {
		logrus.Errorf("Could not validate schema uniqueness: %s", s.ID)
		return err
	}
	return nil
}

func (s Schema) ValidateStatic() error {
	if err := s.ValidateNotEmpty(); err != nil {
		logrus.Error()
		return err
	}

	if err := ValidateSchemaID(s.ID); err != nil {
		logrus.Errorf("Could not validate schema id: %s", s.ID)
		return err
	}

	if err := s.ValidateMetadata(); err != nil {
		logrus.Errorf("Could not validate schema metadata: %s", s.ID)
		return err
	}
	return nil
}

func (s Schema) ValidateNotEmpty() error {
	if s.IsEmpty() {
		return errors.New("schema empty")
	}
	return nil
}

func ValidateSchemaID(id string) error {
	r, err := regexp.Compile(IDRxStr)
	if err != nil {
		return fmt.Errorf("failed to compile regular expression: %s", IDRxStr)
	}

	result := r.Match([]byte(id))
	if !result {
		return fmt.Errorf("ledger schema 'id': %s is not valid against pattern: %s", id, IDRxStr)
	}
	return nil
}

func (s Schema) ValidateMetadata() error {
	if s.Type != util.SchemaTypeReference_v1_0 {
		return fmt.Errorf("invalid type %s", s.Type)
	}
	if s.ModelVersion != util.Version_1_0 {
		return fmt.Errorf("invalid modelVersion %s", s.ModelVersion)
	}
	return nil
}

func (s Schema) ValidateProof(ctx context.Context, provider DIDDocProvider) error {
	if s.Proof == nil {
		return errors.New("no proof on schema")
	}
	keyDef, err := GetKeyDef(ctx, s.Author, s.Proof.GetVerificationMethod(), provider)
	switch {
	case err != nil:
		logrus.WithError(err).Error("could not get key def")
		return err
	case keyDef == nil:
		return fmt.Errorf("could not resolve specified key '%s' in did doc '%s'", s.Proof.GetVerificationMethod(), s.Author)
	}

	key, err := keyDef.GetDecodedPublicKey()
	if err != nil {
		return err
	}
	verifier := &proof.Ed25519Verifier{PubKey: key}
	suite, err := proof.SignatureSuites().GetSuiteForProof(s.GetProof())
	if err != nil {
		return err
	}
	return suite.Verify(s, verifier)
}

func (s Schema) ValidateUniqueness(ctx context.Context, provider SchemaProvider) error {
	record, err := provider(ctx, s.ID)
	if err != nil {
		logrus.WithError(err).Errorf("failure to lookup schema: %s", s.ID)
		return nil
	}
	if record != nil && record.ID != "" && !reflect.DeepEqual(s, *record) {
		return fmt.Errorf("schema already exists: %s", s.ID)
	}
	return nil
}
