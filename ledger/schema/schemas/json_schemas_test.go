package schemas

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSchemas(t *testing.T) {
	schema, metadata, ok := GetSchemas("name")
	assert.True(t, ok)

	nameBytes, err := os.ReadFile("json/name.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, nameBytes)
	assert.Equal(t, string(nameBytes), schema)

	metadataBytes, err := os.ReadFile("json/name_metadata.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, metadataBytes)
	assert.Equal(t, string(metadataBytes), metadata)
}

func TestGetSchemas_BogusSchema(t *testing.T) {
	_, _, ok := GetSchemas("bogus")
	assert.False(t, ok)
}

func TestGetSchemasOrPanic(t *testing.T) {
	schema, metadata := GetSchemasOrPanic("name")

	nameBytes, err := os.ReadFile("json/name.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, nameBytes)
	assert.Equal(t, schema, string(nameBytes))

	metadataBytes, err := os.ReadFile("json/name_metadata.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, metadataBytes)
	assert.Equal(t, metadata, string(metadataBytes))
}

func TestGetSchemasOrPanic_BogusSchema(t *testing.T) {
	assert.Panics(t, func() { GetSchemasOrPanic("bogus") })
}
