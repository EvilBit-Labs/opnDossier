package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

	assert.Empty(t, errs.Errors)
	assert.False(t, errs.HasErrors())

	errs.Add(FieldValidationError{Field: "field1", Message: "error1"})
	assert.Len(t, errs.Errors, 1)
	assert.True(t, errs.HasErrors())

	errs.Add(FieldValidationError{Field: "field2", Message: "error2"})
	assert.Len(t, errs.Errors, 2)
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
