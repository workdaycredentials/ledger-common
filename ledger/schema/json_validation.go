package schema

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	if !isJSON(schema) {
		return fmt.Errorf("schema is not valid json: %s", schema)
	} else if !isJSON(document) {
		return fmt.Errorf("document is not valid json: %s", document)
	}
	return ValidateWithJSONLoader(gojsonschema.NewStringLoader(schema), gojsonschema.NewStringLoader(document))
}

// Validate takes schema and document loaders; the document from the loader is validated against
// the schema from the loader. Nil if good, error if bad
func ValidateWithJSONLoader(schemaLoader, documentLoader gojsonschema.JSONLoader) error {
	// Add custom validator(s) and then ValidateWithJSONLoader
	addRFC3339Validation()
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

// Validate credential is a specific form of validation that understands the format of a credential
// This includes a credential schema that applies to all credentials and a "fields" section which
// has a schema specific to the 'type' defined in the credentialSchema portion of the document.
func ValidateCredential(credentialSchema, credentialSubjectSchema, documentJSON string) error {
	// First ValidateWithJSONLoader against the credential s
	if err := Validate(credentialSchema, documentJSON); err != nil {
		logrus.WithError(err).Error("failed to ValidateWithJSONLoader document json against credentialSchema")
		return err
	}

	// Next unmarshal the credentialSchema to extract the fields object
	var cred credential.VerifiableCredential
	if err := json.Unmarshal([]byte(documentJSON), &cred); err != nil {
		logrus.WithError(err).Error("unable to unmarshal document into JSONSchema model")
		return err
	}
	logrus.Debugf("Unmarshalled credential json: %s", documentJSON)

	// Marshal the credential subject to json to ValidateWithJSONLoader against the provided credential subject s
	credentialSubjectJSONBytes, err := json.Marshal(cred.CredentialSubject)
	if err != nil {
		logrus.WithError(err).Error("could not marshal credential subject to json")
		return err
	}
	credentialSubjectJSON := string(credentialSubjectJSONBytes)
	logrus.Debugf("Unmarshalled credential subject json: %s", credentialSubjectJSON)

	// Validate against the credential subject s
	return Validate(credentialSubjectSchema, credentialSubjectJSON)
}

// ValidateJSONSchema takes in a string that is purported to be a JSON schema (schema definition)
// An error is returned if it is not a valid JSON s, and nil is returned on success
func ValidateJSONSchema(maybeSchema ledger.JSONSchemaMap) error {
	schemaLoader := gojsonschema.NewSchemaLoader()
	schemaLoader.Validate = true
	return schemaLoader.AddSchemas(gojsonschema.NewStringLoader(maybeSchema.ToJSON()))
}

// Validates a schema by finding the right validation method according to the version
// It is possible that multiple validation methods would be supported for a given version,
// so we always choose the validation method created last (heavy assumption here that the versions
// we track are properly ordered).
func ValidateSchemaRequest(ctx context.Context, document interface{}, version string) error {
	validator, err := FindValidatorForVersion(ctx, version)
	if err != nil {
		err := fmt.Errorf("invalid version<%s>", version)
		logrus.WithError(err).Error("unsupported schema version")
		return err
	}

	switch validator {
	case V1:
		return ValidateLedgerSchemaV1(ctx, document)
	default:
		return fmt.Errorf("invalid version<%s>", version)
	}
}

// Custom validation logic
type RFC3339FormatChecker struct{}

// Ensure it meets the gojsonschema.FormatChecker interface
// Try to parse the string as a RFC3339 date-time
func (f RFC3339FormatChecker) IsFormat(input interface{}) bool {

	asString, ok := input.(string)
	if !ok {
		return false
	}
	_, err := time.Parse(time.RFC3339, asString)
	return err == nil
}

// Add custom rfc3339 validator the library
func addRFC3339Validation() {
	gojsonschema.FormatCheckers.Add("date-time-rfc3339", RFC3339FormatChecker{})
}

// True if string is valid JSON, false otherwise
func isJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}
