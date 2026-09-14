package cfgparser

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseError(t *testing.T) {
	t.Run("Error message formatting", func(t *testing.T) {
		err := &ParseError{Line: 10, Column: 25, Message: "unexpected end tag"}
		expected := "parse error at line 10, column 25: unexpected end tag"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("Is method works correctly", func(t *testing.T) {
		err1 := &ParseError{Line: 1, Column: 1, Message: "test error"}
		err2 := &ParseError{Line: 2, Column: 2, Message: "another error"}

		// Test that Is works with same type
		require.ErrorIs(t, err1, &ParseError{})
		require.ErrorIs(t, err2, &ParseError{})

		// Test wrapping
		wrapped := fmt.Errorf("wrapped: %w", err1)
		assert.True(t, IsParseError(wrapped))
	})

	t.Run("As method works correctly", func(t *testing.T) {
		original := &ParseError{Line: 5, Column: 10, Message: "syntax error"}
		wrapped := fmt.Errorf("operation failed: %w", original)

		var parseErr *ParseError
		require.ErrorAs(t, wrapped, &parseErr)
		assert.Equal(t, 5, parseErr.Line)
		assert.Equal(t, 10, parseErr.Column)
		assert.Equal(t, "syntax error", parseErr.Message)
	})
}

func TestValidationError(t *testing.T) {
	t.Run("Error message formatting with path", func(t *testing.T) {
		err := &ValidationError{Path: "opnsense.system.hostname", Message: "invalid hostname format"}
		expected := "validation error at opnsense.system.hostname: invalid hostname format"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("Error message formatting without path", func(t *testing.T) {
		err := &ValidationError{Path: "", Message: "missing required field"}
		expected := "validation error: missing required field"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("Is method works correctly", func(t *testing.T) {
		err1 := &ValidationError{Path: "path.to.field", Message: "invalid value"}
		err2 := &ValidationError{Path: "", Message: "general error"}

		// Test that Is works with same type
		require.ErrorIs(t, err1, &ValidationError{})
		require.ErrorIs(t, err2, &ValidationError{})

		// Test wrapping
		wrapped := fmt.Errorf("validation failed: %w", err1)
		assert.True(t, IsValidationError(wrapped))
	})

	t.Run("As method works correctly", func(t *testing.T) {
		original := &ValidationError{Path: "config.port", Message: "port out of range"}
		wrapped := fmt.Errorf("configuration error: %w", original)

		var validationErr *ValidationError
		require.ErrorAs(t, wrapped, &validationErr)
		assert.Equal(t, "config.port", validationErr.Path)
		assert.Equal(t, "port out of range", validationErr.Message)
	})
}

func TestErrorHelpers(t *testing.T) {
	t.Run("IsParseError helper", func(t *testing.T) {
		parseErr := &ParseError{Line: 1, Column: 1, Message: "test"}
		validationErr := &ValidationError{Path: "path", Message: "test"}
		genericErr := errors.New("generic") //nolint:err113 // Test error

		assert.True(t, IsParseError(parseErr))
		assert.False(t, IsParseError(validationErr))
		assert.False(t, IsParseError(genericErr))

		// Test with wrapped error
		wrapped := fmt.Errorf("wrapped: %w", parseErr)
		assert.True(t, IsParseError(wrapped))
	})

	t.Run("IsValidationError helper", func(t *testing.T) {
		parseErr := &ParseError{Line: 1, Column: 1, Message: "test"}
		validationErr := &ValidationError{Path: "path", Message: "test"}
		genericErr := errors.New("generic") //nolint:err113 // Test error

		assert.False(t, IsValidationError(parseErr))
		assert.True(t, IsValidationError(validationErr))
		assert.False(t, IsValidationError(genericErr))

		// Test with wrapped error
		wrapped := fmt.Errorf("wrapped: %w", validationErr)
		assert.True(t, IsValidationError(wrapped))
	})

	t.Run("GetParseError helper", func(t *testing.T) {
		original := &ParseError{Line: 10, Column: 20, Message: "parse issue"}
		wrapped := fmt.Errorf("operation failed: %w", original)

		extracted := GetParseError(wrapped)
		require.NotNil(t, extracted)
		assert.Equal(t, 10, extracted.Line)
		assert.Equal(t, 20, extracted.Column)
		assert.Equal(t, "parse issue", extracted.Message)

		// Test with non-parse error
		genericErr := errors.New("generic") //nolint:err113 // Test error
		extracted = GetParseError(genericErr)
		assert.Nil(t, extracted)
	})
}

func TestErrorChaining(t *testing.T) {
	t.Run("Multiple levels of wrapping", func(t *testing.T) {
		original := &ParseError{Line: 5, Column: 15, Message: "syntax error"}
		level1 := fmt.Errorf("parsing failed: %w", original)
		level2 := fmt.Errorf("file processing failed: %w", level1)
		level3 := fmt.Errorf("operation failed: %w", level2)

		// Should still be able to unwrap through multiple levels
		assert.True(t, IsParseError(level3))

		extracted := GetParseError(level3)
		require.NotNil(t, extracted)
		assert.Equal(t, original.Line, extracted.Line)
		assert.Equal(t, original.Column, extracted.Column)
		assert.Equal(t, original.Message, extracted.Message)
	})
}

func TestAggregatedValidationError(t *testing.T) {
	t.Run("Error message formatting", func(t *testing.T) {
		// Test with no errors
		aggErr := NewAggregatedValidationError([]ValidationError{})
		assert.Equal(t, "no validation errors", aggErr.Error())

		// Test with single error
		singleErr := NewAggregatedValidationError([]ValidationError{
			{Path: "path.to.field", Message: "invalid value"},
		})
		assert.Contains(t, singleErr.Error(), "invalid value")

		// Test with multiple errors
		multiErr := NewAggregatedValidationError([]ValidationError{
			{Path: "path1", Message: "error1"},
			{Path: "path2", Message: "error2"},
		})
		assert.Contains(t, multiErr.Error(), "validation failed with 2 errors")
		assert.Contains(t, multiErr.Error(), "error1")
		assert.Contains(t, multiErr.Error(), "error2")
		assert.Contains(t, multiErr.Error(), "1. validation error at path1: error1")
		assert.Contains(t, multiErr.Error(), "2. validation error at path2: error2")
	})

	t.Run("Is method works correctly", func(t *testing.T) {
		err1 := NewAggregatedValidationError([]ValidationError{
			{Path: "path1", Message: "error1"},
		})
		err2 := NewAggregatedValidationError([]ValidationError{
			{Path: "path2", Message: "error2"},
		})

		// Test type-only matching with empty struct
		require.ErrorIs(t, err1, &AggregatedValidationError{})
		require.ErrorIs(t, err2, &AggregatedValidationError{})

		// Test exact matching with same errors
		sameErr := NewAggregatedValidationError([]ValidationError{
			{Path: "path1", Message: "error1"},
		})
		require.ErrorIs(t, err1, sameErr)

		// Test exact matching with different errors
		require.NotErrorIs(t, err1, err2)

		// Test wrapping
		wrapped := fmt.Errorf("wrapped: %w", err1)

		var aggErr *AggregatedValidationError
		assert.ErrorAs(t, wrapped, &aggErr)
	})

	t.Run("HasErrors method", func(t *testing.T) {
		// Test with no errors
		emptyErr := NewAggregatedValidationError([]ValidationError{})
		assert.False(t, emptyErr.HasErrors())

		// Test with errors
		withErr := NewAggregatedValidationError([]ValidationError{
			{Path: "path", Message: "error"},
		})
		assert.True(t, withErr.HasErrors())
	})
}
