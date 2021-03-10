package access

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "access"

var Access, AccessMeta = schemas.GetSchemasOrPanic(name)
