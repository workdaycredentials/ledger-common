package address

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "address"

var Address, AddressMeta = schemas.GetSchemasOrPanic(name)
