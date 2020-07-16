package schema

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuilder(t *testing.T) {
	description := "Name Schema"
	attrs := []Attribute{
		{
			Name:     "firstName",
			Type:     String,
			Required: true,
		},
		{
			Name:     "middleName",
			Type:     String,
			Required: false,
		},
		{
			Name:     "lastName",
			Type:     String,
			Required: true,
		},
		{
			Name:       "email",
			Type:       String,
			StringType: &StringType{Format: Email},
			Required:   false,
		},
	}

	t.Run("happy path", func(t *testing.T) {
		b := Builder{
			Name:                 "Name",
			Description:          description,
			AdditionalProperties: false,
			Attributes:           attrs,
		}

		res, err := b.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, res)

		// Verify data
		assert.Equal(t, description, res.Description())
		assert.Equal(t, false, res.AllowsAdditionalProperties())
		assert.Equal(t, []string{"firstName", "lastName"}, res.RequiredFields())

		// Check if it's a valid json schema
		assert.NoError(t, ValidateJSONSchema(res))
	})

	t.Run("missing required field", func(t *testing.T) {
		b := Builder{
			Name:                 "Name",
			AdditionalProperties: false,
			Attributes:           attrs,
		}

		res, err := b.Build()
		assert.Error(t, err)
		assert.Empty(t, res)
	})

	t.Run("invalid type", func(t *testing.T) {
		attrs := []Attribute{
			{
				Name:     "firstName",
				Type:     "badtype",
				Required: true,
			},
		}

		b := Builder{
			Name:                 "Name",
			Description:          description,
			AdditionalProperties: false,
			Attributes:           attrs,
		}

		res, err := b.Build()
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "unknown attr type"))
		assert.Empty(t, res)
	})

	t.Run("duplicate properties", func(t *testing.T) {
		attrs := []Attribute{
			{
				Name:     "firstName",
				Type:     String,
				Required: true,
			},
			{
				Name:     "firstName",
				Type:     String,
				Required: true,
			},
		}

		b := Builder{
			Name:                 "Name",
			Description:          description,
			AdditionalProperties: false,
			Attributes:           attrs,
		}

		res, err := b.Build()
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "duplicate property"))
		assert.Empty(t, res)
	})
}

func TestBuilderMixedTypes(t *testing.T) {
	t.Run("string, number, boolean", func(t *testing.T) {
		description := "Sample Schema"
		attrs := []Attribute{
			{
				Name:       "firstName",
				Type:       String,
				StringType: &StringType{Format: "date"},
				Required:   true,
			},
			{
				Name:       "favoriteTime",
				Type:       String,
				StringType: &StringType{Format: Time},
				Required:   true,
			},
			{
				Name: "age",
				Type: Number,
				NumberType: &NumberType{
					Minimum: 0,
					Maximum: 10,
				},
				Required: true,
			},
			{
				Name:     "awesome",
				Type:     Boolean,
				Required: false,
			},
		}

		b := Builder{
			Name:                 "Sample",
			Description:          description,
			AdditionalProperties: false,
			Attributes:           attrs,
		}

		res, err := b.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, res)

		// Verify data
		assert.Equal(t, description, res.Description())
		assert.Equal(t, false, res.AllowsAdditionalProperties())
		assert.Equal(t, []string{"firstName", "favoriteTime", "age"}, res.RequiredFields())

		// Check if it's a valid json schema
		assert.NoError(t, ValidateJSONSchema(res))
	})

	t.Run("string and array", func(t *testing.T) {
		description := "Sample Schema"
		attrs := []Attribute{
			{
				Name:     "firstName",
				Type:     String,
				Required: true,
			},
			{
				Name: "favoriteDays",
				Type: Array,
				ArrayType: &ArrayType{
					AttributeType: String,
					StringType:    &StringType{Format: DateTime},
				},
				Required: true,
			},
			{
				Name: "favoriteNumbers",
				Type: Array,
				ArrayType: &ArrayType{
					AttributeType: Number,
					NumberType:    &NumberType{Maximum: 404},
				},
				Required: false,
			},
			{
				Name: "favoriteBooleans",
				Type: Array,
				ArrayType: &ArrayType{
					AttributeType: Boolean,
				},
				Required: false,
			},
		}

		b := Builder{
			Name:                 "Sample",
			Description:          description,
			AdditionalProperties: false,
			Attributes:           attrs,
		}

		res, err := b.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, res)

		// Verify data
		assert.Equal(t, description, res.Description())
		assert.Equal(t, false, res.AllowsAdditionalProperties())
		assert.Equal(t, []string{"firstName", "favoriteDays"}, res.RequiredFields())

		// Check if it's a valid json schema
		assert.NoError(t, ValidateJSONSchema(res))
	})

	t.Run("number and object", func(t *testing.T) {
		description := "Sample Schema"
		attrs := []Attribute{
			{
				Name:     "age",
				Type:     Number,
				Required: true,
			},
			{
				Name: "children",
				Type: Object,
				ObjectType: &ObjectType{
					Properties: map[string]Attribute{
						"firstName": {
							Name:     "firstName",
							Type:     String,
							Required: true,
						},
						"age": {
							Name:     "age",
							Type:     Number,
							Required: true,
						},
						"birthdate": {
							Name:       "birthdate",
							Type:       String,
							Required:   true,
							StringType: &StringType{Format: Date},
						},
					},
					RequiredProperties:   []string{"firstName", "age"},
					AdditionalProperties: false,
				},
				Required: true,
			},
		}

		b := Builder{
			Name:                 "Sample",
			Description:          description,
			AdditionalProperties: false,
			Attributes:           attrs,
		}

		res, err := b.Build()
		assert.NoError(t, err)
		assert.NotEmpty(t, res)

		// Verify data
		assert.Equal(t, description, res.Description())
		assert.Equal(t, false, res.AllowsAdditionalProperties())
		assert.Equal(t, []string{"age", "children"}, res.RequiredFields())

		// Check if it's a valid json schema
		assert.NoError(t, ValidateJSONSchema(res))
	})
}
