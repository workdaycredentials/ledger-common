package employment

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "employment"

var Employment, EmploymentMeta = schemas.GetSchemasOrPanic(name)
