package name

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "name"

var Name, NameMeta = schemas.GetSchemasOrPanic(name)
