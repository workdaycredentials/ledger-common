package education

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "education"

var Education, EducationMeta = schemas.GetSchemasOrPanic(name)
