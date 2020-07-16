package schemas

import (
	"fmt"

	"github.com/gobuffalo/packr"
)

var box = packr.NewBox("./json")

const (
	LedgerMetadataSchema string = "ledger_metadata"
)

func GetJSONFile(name string) (string, error) {
	return box.FindString(fmt.Sprintf("%s.json", name))
}

func GetSchemasOrPanic(name string) (schema string, meta string) {
	var err error
	schema, meta, err = GetSchemas(name)
	if err != nil {
		panic(err)
	}
	return
}

// GetSchemas returns the JSON schema and associated metadata. These schemas must have been
func GetSchemas(name string) (schema string, meta string, err error) {
	schema, err = box.FindString(fmt.Sprintf("%s.json", name))
	if err == nil {
		meta, err = box.FindString(fmt.Sprintf("%s_metadata.json", name))
	}
	return
}
