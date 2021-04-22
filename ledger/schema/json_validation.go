package schema

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xeipuuv/gojsonschema"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger"
)

type InvalidSchemaError struct {
	Errors []string
}

func (err InvalidSchemaError) Error() string {
	return fmt.Sprintf("Invalid schema! Errors: %s", strings.Join(err.Errors, ", "))
}

// Validate exists to hide gojsonschema logic within this file
// it is the entry-point to validation logic, requiring the caller pass in valid json strings for each argument
func Validate(schema, document string) error {
	if !IsJSON(schema) {
		return fmt.Errorf("schema is not valid json: %s", schema)
	} else if !IsJSON(document) {
		return fmt.Errorf("document is not valid json: %s", document)
	}
	return ValidateWithJSONLoader(gojsonschema.NewStringLoader(schema), gojsonschema.NewStringLoader(document))
}

// Validate takes schema and document loaders; the document from the loader is validated against
// the schema from the loader. Nil if good, error if bad
func ValidateWithJSONLoader(schemaLoader, documentLoader gojsonschema.JSONLoader) error {
	// Add custom validator(s) and then ValidateWithJSONLoader
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		logrus.WithError(err).Error("failed to ValidateWithJSONLoader document against s")
		return err
	}

	if !result.Valid() {
		// Accumulate errs
		var errs []string
		for _, err := range result.Errors() {
			errs = append(errs, err.String())
		}
		return InvalidSchemaError{Errors: errs}
	}
	return nil
}

// Validate a credential's data is valid against its schema
func ValidateCredential(credentialSubjectSchema, documentJSON string) error {
	var cred credential.VerifiableCredential
	if err := json.Unmarshal([]byte(documentJSON), &cred); err != nil {
		logrus.WithError(err).Error("unable to unmarshal document into JSONSchema model")
		return err
	}
	logrus.Debugf("unmarshalled credential json: %s", documentJSON)

	// Remove the "id" property that is common to each credential
	delete(cred.CredentialSubject, credential.SubjectIDAttribute)

	// Marshal the credential subject to json to ValidateWithJSONLoader against the provided credential subject schema
	credentialSubjectJSONBytes, err := json.Marshal(cred.CredentialSubject)
	if err != nil {
		logrus.WithError(err).Error("could not marshal credential subject to json")
		return err
	}
	credentialSubjectJSON := string(credentialSubjectJSONBytes)
	logrus.Debugf("unmarshalled credential subject json: %s", credentialSubjectJSON)

	// Validate against the credential subject s
	return Validate(credentialSubjectSchema, credentialSubjectJSON)
}

// ValidateJSONSchema takes in a string that is purported to be a JSON schema (schema definition)
// An error is returned if it is not a valid JSON schema, and nil is returned on success
func ValidateJSONSchemaString(maybeSchema string) error {
	var schemaMap ledger.JSONSchemaMap
	if err := json.Unmarshal([]byte(maybeSchema), &schemaMap); err != nil {
		return err
	}
	return ValidateJSONSchema(schemaMap)
}

// ValidateJSONSchema takes in a map that is purported to be a JSON schema (schema definition)
// An error is returned if it is not a valid JSON schema, and nil is returned on success
func ValidateJSONSchema(maybeSchema ledger.JSONSchemaMap) error {
	schemaLoader := gojsonschema.NewSchemaLoader()
	schemaLoader.Validate = true
	return schemaLoader.AddSchemas(gojsonschema.NewStringLoader(maybeSchema.ToJSON()))
}

// Validates a schema by finding the right validation method according to the version
// It is possible that multiple validation methods would be supported for a given version,
// so we always choose the validation method created last (heavy assumption here that the versions
// we track are properly ordered).
func ValidateSchemaRequest(document interface{}, version string) error {
	validator, err := FindValidatorForVersion(version)
	if err != nil {
		err := fmt.Errorf("invalid version<%s>", version)
		logrus.WithError(err).Error("unsupported schema version")
		return err
	}

	switch validator {
	case V1:
		return ValidateLedgerSchemaV1(document)
	default:
		return fmt.Errorf("invalid version<%s>", version)
	}
}

// True if string is valid JSON, false otherwise
func IsJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}
