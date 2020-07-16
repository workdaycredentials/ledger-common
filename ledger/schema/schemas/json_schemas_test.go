package schemas

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSchemas(t *testing.T) {
	schema, metadata, err := GetSchemas("name")
	assert.NoError(t, err)

	nameBytes, err := ioutil.ReadFile("json/name.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, nameBytes)
	assert.Equal(t, schema, string(nameBytes))

	metadataBytes, err := ioutil.ReadFile("json/name_metadata.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, metadataBytes)
	assert.Equal(t, metadata, string(metadataBytes))
}

func TestGetSchemas_BogusSchema(t *testing.T) {
	_, _, err := GetSchemas("bogus")
	assert.Error(t, err)
}

func TestGetSchemasOrPanic(t *testing.T) {
	schema, metadata := GetSchemasOrPanic("name")

	nameBytes, err := ioutil.ReadFile("json/name.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, nameBytes)
	assert.Equal(t, schema, string(nameBytes))

	metadataBytes, err := ioutil.ReadFile("json/name_metadata.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, metadataBytes)
	assert.Equal(t, metadata, string(metadataBytes))
}

func TestGetSchemasOrPanic_BogusSchema(t *testing.T) {
	assert.Panics(t, func() { GetSchemasOrPanic("bogus") })
}
