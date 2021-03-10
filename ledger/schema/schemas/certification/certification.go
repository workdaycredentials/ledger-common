package certification

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "certification"

var Certification, CertificationMeta = schemas.GetSchemasOrPanic(name)
