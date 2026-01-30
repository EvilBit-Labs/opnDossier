package config

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      FieldValidationError
		contains []string
	}{
		{
			name: "basic error",
			err: FieldValidationError{
				Field:   "test_field",
				Message: "test message",
			},
			contains: []string{"test_field", "test message"},
		},
		{
			name: "error with suggestion",
			err: FieldValidationError{
				Field:      "test_field",
				Message:    "test message",
				Suggestion: "try this instead",
			},
			contains: []string{"test_field", "test message", "try this instead"},
		},
		{
			name: "error with value",
			err: FieldValidationError{
				Field:   "test_field",
				Message: "invalid value",
				Value:   "bad_value",
			},
			contains: []string{"test_field", "invalid value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, s := range tt.contains {
				assert.Contains(t, errStr, s)
			}
		})
	}
}

func TestMultiValidationError_Add(t *testing.T) {
	errs := &MultiValidationError{}

	assert.Equal(t, 0, errs.Count())
	assert.False(t, errs.HasErrors())

	errs.Add(FieldValidationError{Field: "field1", Message: "error1"})
	assert.Equal(t, 1, errs.Count())
	assert.True(t, errs.HasErrors())

	errs.Add(FieldValidationError{Field: "field2", Message: "error2"})
	assert.Equal(t, 2, errs.Count())
}

func TestMultiValidationError_Error(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		errs := &MultiValidationError{}
		assert.Equal(t, "no validation errors", errs.Error())
	})

	t.Run("single error", func(t *testing.T) {
		errs := &MultiValidationError{}
		errs.Add(FieldValidationError{Field: "field1", Message: "error1"})
		errStr := errs.Error()
		assert.Contains(t, errStr, "field1")
		assert.Contains(t, errStr, "error1")
	})

	t.Run("multiple errors", func(t *testing.T) {
		errs := &MultiValidationError{}
		errs.Add(FieldValidationError{Field: "field1", Message: "error1"})
		errs.Add(FieldValidationError{Field: "field2", Message: "error2"})
		errStr := errs.Error()
		assert.Contains(t, errStr, "field1")
		assert.Contains(t, errStr, "error1")
		assert.Contains(t, errStr, "field2")
		assert.Contains(t, errStr, "error2")
		assert.Contains(t, errStr, ";") // Errors should be separated
	})
}

func TestErrorFormatter_FormatError(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewErrorFormatterWithWriter(&buf)

	err := &FieldValidationError{
		Field:      "test_field",
		Message:    "invalid value provided",
		Value:      "bad_value",
		Suggestion: "use a valid value instead",
		ValidItems: []string{"option1", "option2", "option3"},
		LineNumber: 10,
	}

	formatter.FormatError(err)
	output := buf.String()

	// Check that all parts are present (allowing for ANSI codes)
	assert.Contains(t, output, "Error:")
	assert.Contains(t, output, "test_field")
	assert.Contains(t, output, "invalid value provided")
	assert.Contains(t, output, "'bad_value'")
	assert.Contains(t, output, "10")
	assert.Contains(t, output, "option1")
	assert.Contains(t, output, "option2")
	assert.Contains(t, output, "option3")
	assert.Contains(t, output, "use a valid value instead")
}

func TestErrorFormatter_FormatError_MinimalError(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewErrorFormatterWithWriter(&buf)

	err := &FieldValidationError{
		Field:   "test_field",
		Message: "basic error",
	}

	formatter.FormatError(err)
	output := buf.String()

	// Check basic content is present
	assert.Contains(t, output, "Error:")
	assert.Contains(t, output, "test_field")
	assert.Contains(t, output, "basic error")

	// Should not contain optional parts
	assert.NotContains(t, output, "Got:")   // No value provided
	assert.NotContains(t, output, "Line:")  // No line number
	assert.NotContains(t, output, "Valid:") // No valid items
}

func TestErrorFormatter_FormatErrors(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewErrorFormatterWithWriter(&buf)

	errs := &MultiValidationError{}
	errs.Add(FieldValidationError{
		Field:   "field1",
		Message: "error1",
	})
	errs.Add(FieldValidationError{
		Field:   "field2",
		Message: "error2",
	})

	formatter.FormatErrors(errs)
	output := buf.String()

	// Check header
	assert.Contains(t, output, "Configuration Validation Failed")
	assert.Contains(t, output, "2")
	assert.Contains(t, output, "errors")

	// Check both errors are present
	assert.Contains(t, output, "field1")
	assert.Contains(t, output, "error1")
	assert.Contains(t, output, "field2")
	assert.Contains(t, output, "error2")
}

func TestErrorFormatter_FormatErrors_Empty(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewErrorFormatterWithWriter(&buf)

	errs := &MultiValidationError{}
	formatter.FormatErrors(errs)

	// Should output nothing for empty errors
	assert.Empty(t, buf.String())
}

func TestErrorFormatter_FormatErrors_SingleError(t *testing.T) {
	var buf bytes.Buffer
	formatter := NewErrorFormatterWithWriter(&buf)

	errs := &MultiValidationError{}
	errs.Add(FieldValidationError{
		Field:   "field1",
		Message: "error1",
	})

	formatter.FormatErrors(errs)
	output := buf.String()

	// Check singular "error" is used
	assert.Contains(t, output, "1")
	assert.Contains(t, output, "error")
	// Make sure there's no separator line for single error
	assert.Equal(t, 1, strings.Count(output, "field1"))
}

func TestNewErrorFormatter(t *testing.T) {
	formatter := NewErrorFormatter()
	require.NotNil(t, formatter)
	// Default formatter should write to stderr
	assert.NotNil(t, formatter.writer)
}

func TestConvertToV2Errors(t *testing.T) {
	legacyErrors := []ValidationError{
		{Field: "field1", Message: "message1"},
		{Field: "field2", Message: "message2"},
	}

	errs := ConvertToV2Errors(legacyErrors)

	require.NotNil(t, errs)
	assert.Equal(t, 2, errs.Count())
	assert.Equal(t, "field1", errs.Errors[0].Field)
	assert.Equal(t, "message1", errs.Errors[0].Message)
	assert.Equal(t, "field2", errs.Errors[1].Field)
	assert.Equal(t, "message2", errs.Errors[1].Message)
}

func TestPluralize(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		singular string
		plural   string
		expected string
	}{
		{"zero uses plural", 0, "error", "errors", "errors"},
		{"one uses singular", 1, "error", "errors", "error"},
		{"two uses plural", 2, "error", "errors", "errors"},
		{"many uses plural", 100, "error", "errors", "errors"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pluralize(tt.count, tt.singular, tt.plural)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultErrorStyles(t *testing.T) {
	styles := defaultErrorStyles()

	// Verify that styles can render content
	// Lipgloss styles return empty string when calling String() without content
	// So we test by rendering some text
	assert.NotEmpty(t, styles.ErrorLabel.Render("test"))
	assert.NotEmpty(t, styles.FieldLabel.Render("test"))
}
