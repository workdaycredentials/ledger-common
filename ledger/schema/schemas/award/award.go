package award

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "award"

var Award, AwardMeta = schemas.GetSchemasOrPanic(name)
