package util

import (
	"regexp"
)

var (
	UUIDRegExp = regexp.MustCompile(`^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$`) // nolint:gochecknoglobals
)

const (
	Version_1_0                     = "1.0"
	SchemaTypeReference_v1_0        = "https://credentials.workday.com/docs/specification/v1.0/schema.json"
	DIDDocTypeReference_v1_0        = "https://credentials.workday.com/docs/specification/v1.0/did-doc.json"
	RevocationTypeReference_v1_0    = "https://credentials.workday.com/docs/specification/v1.0/revocation.json"
	CredentialTypeReference_v1_0    = "https://credentials.workday.com/docs/specification/v1.0/credential.json"
	ProofRequestTypeReference_v1_0  = "https://credentials.workday.com/docs/specification/v1.0/proof-request.json"
	ProofResponseTypeReference_v1_0 = "https://credentials.workday.com/docs/specification/v1.0/proof-response.json"
)
