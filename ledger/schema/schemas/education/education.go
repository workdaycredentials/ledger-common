package education

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "education"

var Education, EducationMeta = schemas.GetSchemasOrPanic(name)
