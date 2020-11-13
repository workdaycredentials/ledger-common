package certification

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "certification"

var Certification, CertificationMeta = schemas.GetSchemasOrPanic(name)
