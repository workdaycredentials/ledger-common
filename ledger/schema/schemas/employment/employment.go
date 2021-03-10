package employment

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "employment"

var Employment, EmploymentMeta = schemas.GetSchemasOrPanic(name)
