package schema

import (
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
)

const (
	expectedSchemaVersion           = "1.0"
	expectedMinorVersionAfterUpdate = "1.1"
	expectedMajorVersionAfterUpdate = "2.0"

	testSchemaID = "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.0"

	messageSchemaMissing = "Updated Schema is missing from input"
)

var (
	didDoc, pk = ledger.GenerateLedgerDIDDoc(proof.Ed25519KeyType, proof.JCSEdSignatureType)
)

func TestValidateSchemaUpdate(t *testing.T) {
	// setup
	input := &UpdateInput{}
	previousSchema := generateSchema(*didDoc.DIDDoc, pk)
	input.PreviousSchema = previousSchema

	// extract previous version number
	schemaIDSplits := strings.Split(input.PreviousSchema.ID, ";")
	assert.Equal(t, schemaIDSplits[2], "version=1.0")

	updatedSchema := &ledger.Schema{}
	err := util.DeepCopy(previousSchema, updatedSchema)
	assert.NoError(t, err)
	input.UpdatedSchema = updatedSchema

	basicSchemaUpdateValidityChecks(t, previousSchema)

	// At this point previous and updated schema are the same
	result, err := ValidateSchemaUpdate(input)
	expectedMessage := "Schema has not been updated"
	assert.EqualError(t, err, expectedMessage)
	assert.False(t, result.Valid)
	assert.Equal(t, expectedMessage, result.Message)

	validateChangesToAdditionalPropertiesField(t, input)

	// list of required has been added to -> MAJOR version change
	validateNewRequiredFieldsAdded(t, input)

	// is the schema name or description updated? -> MINOR
	validateSchemaNameAndDescription(t, input)

	// are any existing attributes format edited? -> MAJOR
	validateEditOfExistingAttributes(t, input)

	// are any existing attributes removed? -> MAJOR version change
	validateRemovalOfExistingAttributes(t, input)

	// has a required attribute been added? -> MINOR
	// has an optional attribute been added? -> MINOR
	validateAdditionOfNewProperty(t, input)

	// check message for correct analysis of version number choice

}

func basicSchemaUpdateValidityChecks(t *testing.T, previousSchema *ledger.Schema) {
	result, err := ValidateSchemaUpdate(nil)
	expectedMessage := "Input is not valid"
	assert.EqualError(t, err, expectedMessage)
	assert.False(t, result.Valid)
	assert.Equal(t, expectedMessage, result.Message)

	input := &UpdateInput{}
	result, err = ValidateSchemaUpdate(input)
	expectedMessage = messageSchemaMissing
	assert.EqualError(t, err, expectedMessage)
	assert.False(t, result.Valid)
	assert.Equal(t, expectedMessage, result.Message)

	input.PreviousSchema = previousSchema
	result, err = ValidateSchemaUpdate(input)
	expectedMessage = messageSchemaMissing
	assert.EqualError(t, err, expectedMessage)
	assert.False(t, result.Valid)
	assert.Equal(t, expectedMessage, result.Message)

	updatedSchema := &ledger.Schema{}
	input.UpdatedSchema = updatedSchema
	result, err = ValidateSchemaUpdate(input)
	expectedMessage = messageSchemaMissing
	assert.EqualError(t, err, expectedMessage)
	assert.False(t, result.Valid)
	assert.Equal(t, expectedMessage, result.Message)

	err = util.DeepCopy(previousSchema, updatedSchema)
	assert.NoError(t, err)
	updatedSchema.Author = ""
	result, err = ValidateSchemaUpdate(input)
	expectedMessage = "Schema Author is invalid"
	assert.EqualError(t, err, expectedMessage)
	assert.False(t, result.Valid)
	assert.Equal(t, expectedMessage, result.Message)

	updatedSchema.Author = "notEqualToPrevious"
	result, err = ValidateSchemaUpdate(input)
	expectedMessage = "Schema Author is invalid"
	assert.EqualError(t, err, expectedMessage)
	assert.False(t, result.Valid)
	assert.Equal(t, expectedMessage, result.Message)

	updatedSchema.Author = previousSchema.Author

	input.UpdatedSchemaCategoryID = "testCategoryID"
	result, err = ValidateSchemaUpdate(input)
	expectedMessage = "Schema Category cannot be updated"
	assert.EqualError(t, err, expectedMessage)
	assert.False(t, result.Valid)
	assert.Equal(t, expectedMessage, result.Message)

	input.PreviousSchemaCategoryID = "testCategoryID"

}

func validateChangesToAdditionalPropertiesField(t *testing.T, input *UpdateInput) {

	previousSchema := input.PreviousSchema
	updatedSchema := input.UpdatedSchema

	// "additionalProperties": false changes to true -> MINOR
	schemaWithAdditionalPropertiesChanged := &ledger.Schema{}
	err := util.DeepCopy(updatedSchema, schemaWithAdditionalPropertiesChanged)
	assert.NoError(t, err)
	assert.False(t, input.PreviousSchema.Schema.AllowsAdditionalProperties())
	schemaWithAdditionalPropertiesChanged.JSONSchema.Schema["additionalProperties"] = true
	input.UpdatedSchema = schemaWithAdditionalPropertiesChanged
	result, err := ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.False(t, result.MajorChange)
	assert.True(t, result.MinorChange)
	assert.Equal(t, expectedMinorVersionAfterUpdate, result.DerivedVersion)

	// "additionalProperties": true changes to false -> MAJOR
	previousSchema.JSONSchema.Schema["additionalProperties"] = true
	schemaWithAdditionalPropertiesChanged.JSONSchema.Schema["additionalProperties"] = false
	input.UpdatedSchema = schemaWithAdditionalPropertiesChanged
	result, err = ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.MajorChange)
	assert.False(t, result.MinorChange)
	assert.Equal(t, expectedMajorVersionAfterUpdate, result.DerivedVersion)

	previousSchema.JSONSchema.Schema["additionalProperties"] = false
}

func validateNewRequiredFieldsAdded(t *testing.T, input *UpdateInput) {

	schemaWithAdditionalRequiredField := &ledger.Schema{}
	err := util.DeepCopy(input.PreviousSchema, schemaWithAdditionalRequiredField)
	assert.NoError(t, err)
	requiredFields := schemaWithAdditionalRequiredField.JSONSchema.Schema.RequiredFields()
	assert.Equal(t, 2, len(requiredFields))
	assert.False(t, ledger.Contains("suffix", requiredFields))
	newRequiredFields := append(requiredFields, "suffix")

	newRequiredFieldsCast := make([]interface{}, len(newRequiredFields))
	for i, f := range newRequiredFields {
		newRequiredFieldsCast[i] = f
	}

	schemaWithAdditionalRequiredField.JSONSchema.Schema["required"] = newRequiredFieldsCast
	input.UpdatedSchema = schemaWithAdditionalRequiredField
	result, err := ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.False(t, result.MajorChange)
	assert.True(t, result.MinorChange)
	assert.Equal(t, expectedMinorVersionAfterUpdate, result.DerivedVersion)

}

func validateSchemaNameAndDescription(t *testing.T, input *UpdateInput) {

	previousSchema := input.PreviousSchema

	schemaWithNameEdited := &ledger.Schema{}
	err := util.DeepCopy(previousSchema, schemaWithNameEdited)
	assert.NoError(t, err)
	schemaWithNameEdited.Name = "editedName"
	input.UpdatedSchema = schemaWithNameEdited
	result, err := ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.False(t, result.MajorChange)
	assert.True(t, result.MinorChange)
	assert.Equal(t, expectedMinorVersionAfterUpdate, result.DerivedVersion)

	schemaWithDescriptionEdited := &ledger.Schema{}
	err = util.DeepCopy(previousSchema, schemaWithDescriptionEdited)
	assert.NoError(t, err)
	schemaWithDescriptionEdited.Schema["description"] = "editedDescription"
	input.UpdatedSchema = schemaWithDescriptionEdited
	result, err = ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.False(t, result.MajorChange)
	assert.True(t, result.MinorChange)
	assert.Equal(t, expectedMinorVersionAfterUpdate, result.DerivedVersion)
}

func validateEditOfExistingAttributes(t *testing.T, input *UpdateInput) {

	// are any existing attributes format edited? -> MAJOR
	schemaWithPropertyFormatEdited := &ledger.Schema{}
	err := util.DeepCopy(input.PreviousSchema, schemaWithPropertyFormatEdited)
	assert.NoError(t, err)
	withFieldEdited := schemaWithPropertyFormatEdited.JSONSchema.Schema["properties"]
	withFieldEditedCast := withFieldEdited.(map[string]interface{})
	currentField := withFieldEditedCast["suffix"]
	currentFieldCast := currentField.(map[string]interface{})
	currentFieldCast["format"] = "anotherFormat"
	schemaWithPropertyFormatEdited.JSONSchema.Schema["properties"] = withFieldEditedCast
	input.UpdatedSchema = schemaWithPropertyFormatEdited
	result, err := ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.MajorChange)
	assert.False(t, result.MinorChange)
	assert.Equal(t, expectedMajorVersionAfterUpdate, result.DerivedVersion)

	// are any existing attributes type edited? -> MAJOR
	schemaWithPropertyTypeEdited := &ledger.Schema{}
	err = util.DeepCopy(input.PreviousSchema, schemaWithPropertyTypeEdited)
	assert.NoError(t, err)
	withFieldEdited = schemaWithPropertyTypeEdited.JSONSchema.Schema["properties"]
	withFieldEditedCast = withFieldEdited.(map[string]interface{})
	currentField = withFieldEditedCast["suffix"]
	currentFieldCast = currentField.(map[string]interface{})
	currentFieldCast["type"] = "date"
	schemaWithPropertyTypeEdited.JSONSchema.Schema["properties"] = withFieldEditedCast
	input.UpdatedSchema = schemaWithPropertyTypeEdited
	result, err = ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.MajorChange)
	assert.False(t, result.MinorChange)
	assert.Equal(t, expectedMajorVersionAfterUpdate, result.DerivedVersion)
}

func validateRemovalOfExistingAttributes(t *testing.T, input *UpdateInput) {
	schemaWithPropertyRemoved := &ledger.Schema{}
	err := util.DeepCopy(input.PreviousSchema, schemaWithPropertyRemoved)
	assert.NoError(t, err)
	requiredFieldToRemove := schemaWithPropertyRemoved.JSONSchema.Schema.RequiredFields()[0]
	withFieldRemoved := schemaWithPropertyRemoved.JSONSchema.Schema["properties"]
	withFieldRemovedCast := withFieldRemoved.(map[string]interface{})
	delete(withFieldRemovedCast, requiredFieldToRemove)
	schemaWithPropertyRemoved.JSONSchema.Schema["properties"] = withFieldRemovedCast
	input.UpdatedSchema = schemaWithPropertyRemoved
	result, err := ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.MajorChange)
	assert.False(t, result.MinorChange)
	assert.Equal(t, expectedMajorVersionAfterUpdate, result.DerivedVersion)
}

func validateAdditionOfNewProperty(t *testing.T, input *UpdateInput) {
	newPropertyName := "someNewPropertyName"

	schemaWithPropertyAdded := &ledger.Schema{}
	err := util.DeepCopy(input.PreviousSchema, schemaWithPropertyAdded)
	assert.NoError(t, err)

	props := schemaWithPropertyAdded.JSONSchema.Schema["properties"]
	propsCast := props.(map[string]interface{})

	newProperty := make(map[string]string)
	newProperty["type"] = "someNewPropertyNameType"
	newProperty["format"] = "someNewPropertyNameFormat"
	propsCast[newPropertyName] = newProperty
	schemaWithPropertyAdded.JSONSchema.Schema["properties"] = propsCast
	input.UpdatedSchema = schemaWithPropertyAdded
	result, err := ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.False(t, result.MajorChange)
	assert.True(t, result.MinorChange)
	assert.Equal(t, expectedMinorVersionAfterUpdate, result.DerivedVersion)

	// now add new property name to required and check
	requiredFields := schemaWithPropertyAdded.JSONSchema.Schema.RequiredFields()
	assert.Equal(t, 2, len(requiredFields))
	assert.False(t, ledger.Contains(newPropertyName, requiredFields))
	newRequiredFields := append(requiredFields, newPropertyName)

	newRequiredFieldsCast := make([]interface{}, len(newRequiredFields))
	for i, f := range newRequiredFields {
		newRequiredFieldsCast[i] = f
	}

	schemaWithPropertyAdded.JSONSchema.Schema["required"] = newRequiredFieldsCast
	input.UpdatedSchema = schemaWithPropertyAdded
	result, err = ValidateSchemaUpdate(input)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.False(t, result.MajorChange)
	assert.True(t, result.MinorChange)
	assert.Equal(t, expectedMinorVersionAfterUpdate, result.DerivedVersion)
}

func TestMajorIncrementHasZeroMinorVersion(t *testing.T) {
	incrementedVersionNumber, err := incrementMajorVersion("12.34")
	assert.NoError(t, err)
	assert.Equal(t, "13.0", incrementedVersionNumber)
}

func TestIncrementVersionNumber(t *testing.T) {
	previousVersion := expectedSchemaVersion
	incremented, err := incrementMajorVersion(previousVersion)
	assert.NoError(t, err)
	assert.Equal(t, "2.0", incremented)

	// ----

	previousVersion = expectedSchemaVersion
	incremented, err = incrementMinorVersion(previousVersion)
	assert.NoError(t, err)
	assert.Equal(t, "1.1", incremented)

	// ----

	previousVersion = "3.15"
	incremented, err = incrementMinorVersion(previousVersion)
	assert.NoError(t, err)
	assert.Equal(t, "3.16", incremented)
}

func TestIncrementIntAsString(t *testing.T) {
	one := "1"
	result, err := incrementIntAsString(one)
	assert.NoError(t, err)
	assert.Equal(t, "2", result)

	ten := "10"
	result, err = incrementIntAsString(ten)
	assert.NoError(t, err)
	assert.Equal(t, "11", result)
}

func TestStringToVersion(t *testing.T) {
	version, e := VersionFromStr("1.0")
	assert.Nil(t, e)
	assert.Equal(t, Version{1, 0}, version)

	version, e = VersionFromStr("v1.1")
	assert.Equal(t, UnRecognisedVersionError{"v1.1"}, e)
	assert.Equal(t, Version{}, version)

	version, e = VersionFromStr("1.a")
	assert.Equal(t, UnRecognisedVersionError{"1.a"}, e)
	assert.Equal(t, Version{}, version)

	version, e = VersionFromStr("a.1")
	assert.Equal(t, UnRecognisedVersionError{"a.1"}, e)
	assert.Equal(t, Version{}, version)

	version, e = VersionFromStr("v.1")
	assert.Equal(t, UnRecognisedVersionError{"v.1"}, e)
	assert.Equal(t, Version{}, version)

	version, e = VersionFromStr("1.")
	assert.Equal(t, UnRecognisedVersionError{"1."}, e)
	assert.Equal(t, Version{}, version)

	version, e = VersionFromStr(".1")
	assert.Equal(t, UnRecognisedVersionError{".1"}, e)
	assert.Equal(t, Version{}, version)
}

func TestExtractAuthorDIDFromID(t *testing.T) {
	id, err := ExtractSchemaAuthorDID(testSchemaID)
	assert.NoError(t, err)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", id)
}

func TestExtractResourceIDFromSchemaID(t *testing.T) {
	resourceID, err := ExtractSchemaResourceID(testSchemaID)
	assert.NoError(t, err)
	assert.Equal(t, "112f1a23ce1747b199265dfcc235049b", resourceID)
}

func generateSchema(didDoc did.DIDDoc, privKey ed25519.PrivateKey) *ledger.Schema {
	testSchema := `{
	  "$schema": "http://json-schema.org/draft-07/schema#",
	  "description": "Name",
	  "type": "object",
	  "properties": {
		"title": {
		  "type": "string"
		},
		"firstName": {
		  "type": "string"
		},
		"lastName": {
		  "type": "string"
		},
		"middleName": {
		  "type": "string"
		},
		"suffix": {
		  "type": "string"
		}
	  },
	  "required": ["firstName", "lastName"],
	  "additionalProperties": false
	 }
	`
	var s ledger.JSONSchemaMap
	if err := json.Unmarshal([]byte(testSchema), &s); err != nil {
		panic(err)
	}
	signer, err := proof.NewEd25519Signer(privKey, didDoc.PublicKey[0].ID)
	if err != nil {
		panic(err)
	}
	schema, err := ledger.GenerateLedgerSchema("Name", didDoc.ID, signer, proof.WorkEdSignatureType, s)
	if err != nil {
		panic(err)
	}
	return schema
}
