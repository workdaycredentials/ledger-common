package presentation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func shite(a, b *time.Time) bool { return !a.Equal(*b) }

func TestDateComparison(t *testing.T) {

	t1 := time.Date(2016, time.August, 15, 0, 0, 0, 0, time.UTC)
	sameAsT1 := time.Date(2016, time.August, 15, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2020, time.February, 16, 0, 0, 0, 0, time.UTC)

	// equals
	equals := dateComparisons["equals"]
	t1Equals := equals(&t1, &sameAsT1)
	assert.True(t, t1Equals)
	t1EqualsFail := equals(&t1, &t2)
	assert.False(t, t1EqualsFail)

	// notEquals
	notEquals := dateComparisons["notEquals"]
	t1NotEquals := notEquals(&t1, &sameAsT1)
	assert.False(t, t1NotEquals)
	t1NotEqualsFail := notEquals(&t1, &t2)
	assert.True(t, t1NotEqualsFail)

	// lessThan
	lessThan := dateComparisons["lessThan"]
	t1IsLessThanT2 := lessThan(&t1, &t2)
	assert.True(t, t1IsLessThanT2)
	swapT1IsLessThanT2 := lessThan(&t2, &t1)
	assert.False(t, swapT1IsLessThanT2)
	equalShouldBeFalse := lessThan(&t1, &sameAsT1)
	assert.False(t, equalShouldBeFalse)

	// greaterThan
	greaterThan := dateComparisons["greaterThan"]
	t2IsGreaterThanT1 := greaterThan(&t2, &t1)
	assert.True(t, t2IsGreaterThanT1)
	swapT2IsGreaterThanT1 := greaterThan(&t1, &t2)
	assert.False(t, swapT2IsGreaterThanT1)
	equalShouldBeFalse2 := greaterThan(&t1, &sameAsT1)
	assert.False(t, equalShouldBeFalse2)

	// lessThanOrEqualTo
	lessThanOrEqualTo := dateComparisons["lessThanOrEqualTo"]
	t1IsLessThanOrEqualToT2 := lessThanOrEqualTo(&t1, &t2)
	assert.True(t, t1IsLessThanOrEqualToT2)
	swapT1IsLessThanOrEqualToT2 := lessThanOrEqualTo(&t2, &t1)
	assert.False(t, swapT1IsLessThanOrEqualToT2)
	equalShouldBeTrue := lessThanOrEqualTo(&t1, &sameAsT1)
	assert.True(t, equalShouldBeTrue)

	// greaterThanOrEqualTo
	greaterThanOrEqualTo := dateComparisons["greaterThanOrEqualTo"]
	t1IsGreaterThanOrEqualToT2 := greaterThanOrEqualTo(&t1, &t2)
	assert.False(t, t1IsGreaterThanOrEqualToT2)
	swapT1IsGreaterThanOrEqualToT2 := greaterThanOrEqualTo(&t2, &t1)
	assert.True(t, swapT1IsGreaterThanOrEqualToT2)
	equalShouldBeTrue2 := greaterThanOrEqualTo(&t1, &sameAsT1)
	assert.True(t, equalShouldBeTrue2)

}
