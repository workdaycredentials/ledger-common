package payslip

import "go.wday.io/credentials-open-source/ledger-common/ledger/schema/schemas"

const name = "payslip"

var Payslip, PayslipMeta = schemas.GetSchemasOrPanic(name)
