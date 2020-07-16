package schema

import (
	"fmt"

	"github.com/gobuffalo/packr"
)

var box = packr.NewBox(".")

type Schema string

const (
	VerifiableCredentialSchema Schema = "verifiable-credential-schema"
)

func GetSchema(name Schema) (string, error) {
	return box.FindString(fmt.Sprintf("%s.json", name))
}
