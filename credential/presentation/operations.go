package presentation

import (
	"strings"
	"time"
)

// Binary string operators
var stringComparisons = map[string]func(string, string) bool{ //nolint:gochecknoglobals
	"equals":         func(a, b string) bool { return a == b },
	"equalsFoldCase": strings.EqualFold,
	"notEquals":      func(a, b string) bool { return a != b },
	"beginsWith":     strings.HasPrefix,
	"endsWith":       strings.HasSuffix,
	"contains":       strings.Contains,
	"substring":      func(a, b string) bool { return strings.Contains(b, a) },
}

// Binary number operators
var numberComparisons = map[string]func(float64, float64) bool{ //nolint:gochecknoglobals
	"equals":               func(a, b float64) bool { return a == b },
	"notEquals":            func(a, b float64) bool { return a != b },
	"lessThan":             func(a, b float64) bool { return a < b },
	"greaterThan":          func(a, b float64) bool { return a > b },
	"lessThanOrEqualTo":    func(a, b float64) bool { return a <= b },
	"greaterThanOrEqualTo": func(a, b float64) bool { return a >= b },
}

/*
From go docs https://golang.org/pkg/time/#example_Time_Equal:

 Equal reports whether t and u represent the same time instant. Two times can be equal even if they are in different locations.
For example, 6:00 +0200 and 4:00 UTC are Equal. See the documentation on the Time type for the pitfalls of using == with
Time values; most code should use Equal instead.`

Simple golang "==", "<", ">", etc. operations will not work in many cases. Conversion to a date object resolves these issues.
so long as conversion is also supported by the golang lib
*/

// Binary date operators
var dateComparisons = map[string]func(*time.Time, *time.Time) bool{ //nolint:gochecknoglobals
	"equals":               func(a, b *time.Time) bool { return a.Equal(*b) },
	"notEquals":            func(a, b *time.Time) bool { return !a.Equal(*b) },
	"lessThan":             func(a, b *time.Time) bool { return b.Before(*a) },
	"greaterThan":          func(a, b *time.Time) bool { return b.After(*a) },
	"lessThanOrEqualTo":    func(a, b *time.Time) bool { return a.Equal(*b) || b.Before(*a) },
	"greaterThanOrEqualTo": func(a, b *time.Time) bool { return a.Equal(*b) || b.After(*a) },
}
