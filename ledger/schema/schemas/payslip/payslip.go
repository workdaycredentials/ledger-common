package payslip

import "github.com/workdaycredentials/ledger-common/ledger/schema/schemas"

const name = "payslip"

var Payslip, PayslipMeta = schemas.GetSchemasOrPanic(name)
