package name

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "name"

var Name, NameMeta = schemas.GetSchemasOrPanic(name)
