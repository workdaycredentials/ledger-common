package access

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "access"

var Access, AccessMeta = schemas.GetSchemasOrPanic(name)
