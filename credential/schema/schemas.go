package schema

import (
	"embed"
	"errors"
)

//go:embed verifiable-credential-schema.json
var f embed.FS
var vcSchema, _ = f.ReadFile("verifiable-credential-schema.json")

func GetVCSchema() (string, error) {
	if len(vcSchema) == 0 {
		return "", errors.New("cannot get vc schema")
	}
	return string(vcSchema), nil
}
