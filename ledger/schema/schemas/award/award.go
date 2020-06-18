package award

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "award"

var Award, AwardMeta = schemas.GetSchemasOrPanic(name)
