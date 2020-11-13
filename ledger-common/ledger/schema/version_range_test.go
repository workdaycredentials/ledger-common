package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifySchemaInSpecifiedRange(t *testing.T) {
	rangeStr := "1.0"
	isInRange, err := IDIsInVersionRange(testSchemaID, rangeStr)
	assert.NoError(t, err)
	assert.True(t, isInRange)
}

func TestVerifySchemaOutOfSpecifiedRange(t *testing.T) {
	badMajorV := "4.0"
	badMinorV := "1.4"
	isInRange, err := IDIsInVersionRange(testSchemaID, badMajorV)
	assert.NoError(t, err)
	assert.False(t, isInRange)

	isInRange, err = IDIsInVersionRange(testSchemaID, badMinorV)
	assert.NoError(t, err)
	assert.False(t, isInRange)
}

func TestVerifySchemaInRangeCaretCase(t *testing.T) {
	for _, ibt := range inBoundTestsCaret {
		expected := ibt
		t.Run(ibt.name, func(t *testing.T) {
			isInRange, err := IDIsInVersionRange(expected.id, expected.rng)
			assert.Equal(t, expected.err, err)
			assert.Equal(t, expected.want, isInRange)
		})
	}
}

func TestVerifySchemaOutOfRangeCaretCase(t *testing.T) {
	for _, obt := range outOfBoundTestsCaret {
		expected := obt
		t.Run(expected.name, func(t *testing.T) {
			isInRange, err := IDIsInVersionRange(expected.id, expected.rng)
			assert.Equal(t, expected.err, err)
			assert.Equal(t, expected.want, isInRange)
		})
	}
}

func TestVerifySchemaInRangeMinorWildCard(t *testing.T) {
	for _, ibt := range inBoundTestsMinorWildCard {
		expected := ibt
		t.Run(expected.name, func(t *testing.T) {
			isInRange, err := IDIsInVersionRange(expected.id, expected.rng)
			assert.Equal(t, expected.err, err)
			assert.Equal(t, expected.want, isInRange)
		})
	}
}

func TestVerifySchemaOutOfRangeMinorWildCard(t *testing.T) {
	for _, obt := range outOfBoundTestsMinorWildCard {
		expected := obt
		t.Run(expected.name, func(t *testing.T) {
			isInRange, err := IDIsInVersionRange(expected.id, expected.rng)
			assert.Equal(t, expected.err, err)
			assert.Equal(t, expected.want, isInRange)
		})
	}
}

func TestVerifySchemaInRangeMajorWildCard(t *testing.T) {
	for _, ibt := range inBoundTestsMajorWildCard {
		expected := ibt
		t.Run(expected.name, func(t *testing.T) {
			isInRange, err := IDIsInVersionRange(expected.id, expected.rng)
			assert.Equal(t, expected.err, err)
			assert.Equal(t, expected.want, isInRange)
		})
	}
}

func TestInRangeWithBadVersion(t *testing.T) {
	badVersionInId := "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.2.0"
	isInRange, err := IDIsInVersionRange(badVersionInId, "1.x")
	assert.Equal(t, IDFormatErr{badVersionInId}, err)
	assert.False(t, isInRange)
}

func TestInRangeWithBadRanage(t *testing.T) {
	badVersionInId := "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.0"
	rangeStr := "1.x.4"
	isInRange, err := IDIsInVersionRange(badVersionInId, rangeStr)
	assert.Equal(t, UnRecognisedRangeError{rangeStr}, err)
	assert.False(t, isInRange)
}

var inRange = true
var outOfRangeRange = !inRange

var inBoundTestsCaret = []struct {
	name string
	id   string
	rng  string
	want bool
	err  error
}{
	{
		name: "1.0 in ^1.0",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.0",
		rng:  "^1.0",
		want: inRange,
		err:  nil,
	},
	{
		name: "1.999999 in ^1.1",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.999999",
		rng:  "^1.1",
		want: inRange,
		err:  nil,
	},
}

var outOfBoundTestsCaret = []struct {
	name string
	id   string
	rng  string
	want bool
	err  error
}{
	{
		name: "1.0 in ^1.1",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.0",
		rng:  "^1.1",
		want: outOfRangeRange,
		err:  nil,
	},
	{
		name: "0.1 in ^1.1",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=0.1",
		rng:  "^1.1",
		want: outOfRangeRange,
		err:  nil,
	},
	{
		name: "2.0 in ^1.0",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=2.0",
		rng:  "^1.0",
		want: outOfRangeRange,
		err:  nil,
	},
}

var inBoundTestsMinorWildCard = []struct {
	name string
	id   string
	rng  string
	want bool
	err  error
}{
	{
		name: "1.0 in 1.x",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.0",
		rng:  "1.x",
		want: inRange,
		err:  nil,
	},
	{
		name: "1.0 in 1.*",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.0",
		rng:  "1.*",
		want: inRange,
		err:  nil,
	},
	{
		name: "1.999999 in 1.x",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.999999",
		rng:  "1.x",
		want: inRange,
		err:  nil,
	},
	{
		name: "1.999999 in 1.*",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=1.999999",
		rng:  "1.*",
		want: inRange,
		err:  nil,
	},
}

var outOfBoundTestsMinorWildCard = []struct {
	name string
	id   string
	rng  string
	want bool
	err  error
}{
	{
		name: "2.0 in 1.x",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=2.0",
		rng:  "1.x",
		want: outOfRangeRange,
		err:  nil,
	},
	{
		name: "2.0 in 1.*",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=2.0",
		rng:  "1.*",
		want: outOfRangeRange,
		err:  nil,
	},
	{
		name: "0.1111111 in 1.x",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=0.1111111",
		rng:  "1.x",
		want: outOfRangeRange,
		err:  nil,
	},
	{
		name: "0.1111111 in 1.*",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=0.1111111",
		rng:  "1.*",
		want: outOfRangeRange,
		err:  nil,
	},
}

var inBoundTestsMajorWildCard = []struct {
	name string
	id   string
	rng  string
	want bool
	err  error
}{
	{
		name: "2.0 in x",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=2.0",
		rng:  "x",
		want: inRange,
		err:  nil,
	},
	{
		name: "2.0 in *",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=2.0",
		rng:  "*",
		want: inRange,
		err:  nil,
	},
	{
		name: "111111.3333330 in x",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=111111.3333330",
		rng:  "x",
		want: inRange,
		err:  nil,
	},
	{
		name: "111111.3333330 in *",
		id:   "did:work:6sYe1y3zXhmyrBkgHgAgaq;id=112f1a23ce1747b199265dfcc235049b;version=111111.3333330",
		rng:  "*",
		want: inRange,
		err:  nil,
	},
}
