package address

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "address"

var Address, AddressMeta = schemas.GetSchemasOrPanic(name)
