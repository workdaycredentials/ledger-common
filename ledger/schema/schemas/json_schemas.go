package schemas

import (
	"embed"
	"fmt"

	"github.com/pkg/errors"
)

//go:embed json/*
var f embed.FS
var files = loadJSONs(f)

const (
	LedgerMetadataSchema string = "ledger_metadata"
)

func GetJSONFile(name string) (string, error) {
	file, ok := files[fmt.Sprintf("%s.json", name)]
	if !ok {
		return "", errors.Errorf("cannot get file %s", name)
	}
	return file, nil
}

func GetSchemasOrPanic(name string) (schema string, meta string) {
	schema, meta, ok := GetSchemas(name)
	if !ok {
		panic(errors.Errorf("cannot get schema %s", name))
	}
	return schema, meta
}

// GetSchemas returns the JSON schema and associated metadata. These schemas must have been
func GetSchemas(name string) (schema string, meta string, ok bool) {
	schema, ok = files[fmt.Sprintf("%s.json", name)]
	if ok {
		meta, ok = files[fmt.Sprintf("%s_metadata.json", name)]
	}
	return schema, meta, ok
}

func loadJSONs(fs embed.FS) map[string]string {
	dirEntries, err := fs.ReadDir("json")
	if err != nil {
		panic(err)
	}
	jsonMap := map[string]string{}
	for _, entry := range dirEntries {
		content, _ := f.ReadFile(fmt.Sprintf("json/%s", entry.Name()))
		jsonMap[entry.Name()] = string(content)
	}
	return jsonMap
}
