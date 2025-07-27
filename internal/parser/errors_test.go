package parser

import (
	"encoding/xml"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseError(t *testing.T) {
	t.Run("Error message formatting", func(t *testing.T) {
		err := NewParseError(10, 25, "unexpected end tag")
		expected := "parse error at line 10, column 25: unexpected end tag"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("Is method works correctly", func(t *testing.T) {
		err1 := NewParseError(1, 1, "test error")
		err2 := NewParseError(2, 2, "another error")

		// Test that Is works with same type
		assert.True(t, errors.Is(err1, &ParseError{}))
		assert.True(t, errors.Is(err2, &ParseError{}))

		// Test wrapping
		wrapped := fmt.Errorf("wrapped: %w", err1)
		assert.True(t, IsParseError(wrapped))
	})

	t.Run("As method works correctly", func(t *testing.T) {
		original := NewParseError(5, 10, "syntax error")
		wrapped := fmt.Errorf("operation failed: %w", original)

		var parseErr *ParseError
		require.True(t, errors.As(wrapped, &parseErr))
		assert.Equal(t, 5, parseErr.Line)
		assert.Equal(t, 10, parseErr.Column)
		assert.Equal(t, "syntax error", parseErr.Message)
	})
}

func TestValidationError(t *testing.T) {
	t.Run("Error message formatting with path", func(t *testing.T) {
		err := NewValidationError("opnsense.system.hostname", "invalid hostname format")
		expected := "validation error at opnsense.system.hostname: invalid hostname format"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("Error message formatting without path", func(t *testing.T) {
		err := NewValidationError("", "missing required field")
		expected := "validation error: missing required field"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("Is method works correctly", func(t *testing.T) {
		err1 := NewValidationError("path.to.field", "invalid value")
		err2 := NewValidationError("", "general error")

		// Test that Is works with same type
		assert.True(t, errors.Is(err1, &ValidationError{}))
		assert.True(t, errors.Is(err2, &ValidationError{}))

		// Test wrapping
		wrapped := fmt.Errorf("validation failed: %w", err1)
		assert.True(t, IsValidationError(wrapped))
	})

	t.Run("As method works correctly", func(t *testing.T) {
		original := NewValidationError("config.port", "port out of range")
		wrapped := fmt.Errorf("configuration error: %w", original)

		var validationErr *ValidationError
		require.True(t, errors.As(wrapped, &validationErr))
		assert.Equal(t, "config.port", validationErr.Path)
		assert.Equal(t, "port out of range", validationErr.Message)
	})
}

func TestWrapXMLSyntaxError(t *testing.T) {
	t.Run("Wrap xml.SyntaxError with element path", func(t *testing.T) {
		xmlErr := &xml.SyntaxError{
			Msg:  "XML syntax error: unexpected EOF",
			Line: 15,
		}

		wrapped := WrapXMLSyntaxError(xmlErr, "opnsense.interfaces.lan")

		var parseErr *ParseError
		require.True(t, errors.As(wrapped, &parseErr))
		assert.Equal(t, 15, parseErr.Line)
		assert.Equal(t, 0, parseErr.Column) // xml.SyntaxError doesn't provide column info
		assert.Contains(t, parseErr.Message, "XML syntax error: unexpected EOF")
		assert.Contains(t, parseErr.Message, "opnsense.interfaces.lan")
	})

	t.Run("Wrap xml.SyntaxError without element path", func(t *testing.T) {
		xmlErr := &xml.SyntaxError{
			Msg:  "expected element name after <",
			Line: 5,
		}

		wrapped := WrapXMLSyntaxError(xmlErr, "")

		var parseErr *ParseError
		require.True(t, errors.As(wrapped, &parseErr))
		assert.Equal(t, 5, parseErr.Line)
		assert.Equal(t, 0, parseErr.Column) // xml.SyntaxError doesn't provide column info
		assert.Equal(t, "expected element name after <", parseErr.Message)
	})

	t.Run("Wrap non-XML error", func(t *testing.T) {
		genericErr := errors.New("some other error") //nolint:err113 // Test error

		wrapped := WrapXMLSyntaxError(genericErr, "some.path")

		var parseErr *ParseError
		require.True(t, errors.As(wrapped, &parseErr))
		assert.Equal(t, 0, parseErr.Line)
		assert.Equal(t, 0, parseErr.Column)
		assert.Equal(t, "XML error: some other error", parseErr.Message)
	})

	t.Run("Wrap nil error", func(t *testing.T) {
		wrapped := WrapXMLSyntaxError(nil, "some.path")
		assert.Nil(t, wrapped)
	})
}

func TestBuildElementPath(t *testing.T) {
	t.Run("Build path from multiple elements", func(t *testing.T) {
		elements := []string{"opnsense", "system", "hostname"}
		path := BuildElementPath(elements)
		assert.Equal(t, "opnsense.system.hostname", path)
	})

	t.Run("Build path from single element", func(t *testing.T) {
		elements := []string{"root"}
		path := BuildElementPath(elements)
		assert.Equal(t, "root", path)
	})

	t.Run("Build path from empty slice", func(t *testing.T) {
		elements := []string{}
		path := BuildElementPath(elements)
		assert.Equal(t, "", path)
	})
}

func TestErrorHelpers(t *testing.T) {
	t.Run("IsParseError helper", func(t *testing.T) {
		parseErr := NewParseError(1, 1, "test")
		validationErr := NewValidationError("path", "test")
		genericErr := errors.New("generic") //nolint:err113 // Test error

		assert.True(t, IsParseError(parseErr))
		assert.False(t, IsParseError(validationErr))
		assert.False(t, IsParseError(genericErr))

		// Test with wrapped error
		wrapped := fmt.Errorf("wrapped: %w", parseErr)
		assert.True(t, IsParseError(wrapped))
	})

	t.Run("IsValidationError helper", func(t *testing.T) {
		parseErr := NewParseError(1, 1, "test")
		validationErr := NewValidationError("path", "test")
		genericErr := errors.New("generic") //nolint:err113 // Test error

		assert.False(t, IsValidationError(parseErr))
		assert.True(t, IsValidationError(validationErr))
		assert.False(t, IsValidationError(genericErr))

		// Test with wrapped error
		wrapped := fmt.Errorf("wrapped: %w", validationErr)
		assert.True(t, IsValidationError(wrapped))
	})

	t.Run("GetParseError helper", func(t *testing.T) {
		original := NewParseError(10, 20, "parse issue")
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

	t.Run("GetValidationError helper", func(t *testing.T) {
		original := NewValidationError("config.value", "invalid format")
		wrapped := fmt.Errorf("validation failed: %w", original)

		extracted := GetValidationError(wrapped)
		require.NotNil(t, extracted)
		assert.Equal(t, "config.value", extracted.Path)
		assert.Equal(t, "invalid format", extracted.Message)

		// Test with non-validation error
		genericErr := errors.New("generic") //nolint:err113 // Test error
		extracted = GetValidationError(genericErr)
		assert.Nil(t, extracted)
	})
}

func TestErrorChaining(t *testing.T) {
	t.Run("Multiple levels of wrapping", func(t *testing.T) {
		original := NewParseError(5, 15, "syntax error")
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
			*NewValidationError("path.to.field", "invalid value"),
		})
		assert.Contains(t, singleErr.Error(), "invalid value")

		// Test with multiple errors
		multiErr := NewAggregatedValidationError([]ValidationError{
			*NewValidationError("path1", "error1"),
			*NewValidationError("path2", "error2"),
		})
		assert.Contains(t, multiErr.Error(), "validation failed with 2 errors")
		assert.Contains(t, multiErr.Error(), "error1")
		assert.Contains(t, multiErr.Error(), "and 1 more")
	})

	t.Run("Is method works correctly", func(t *testing.T) {
		err1 := NewAggregatedValidationError([]ValidationError{
			*NewValidationError("path1", "error1"),
		})
		err2 := NewAggregatedValidationError([]ValidationError{
			*NewValidationError("path2", "error2"),
		})

		// Test type-only matching with empty struct
		assert.True(t, errors.Is(err1, &AggregatedValidationError{}))
		assert.True(t, errors.Is(err2, &AggregatedValidationError{}))

		// Test exact matching with same errors
		sameErr := NewAggregatedValidationError([]ValidationError{
			*NewValidationError("path1", "error1"),
		})
		assert.True(t, errors.Is(err1, sameErr))

		// Test exact matching with different errors
		assert.False(t, errors.Is(err1, err2))

		// Test wrapping
		wrapped := fmt.Errorf("wrapped: %w", err1)
		var aggErr *AggregatedValidationError
		assert.True(t, errors.As(wrapped, &aggErr))
	})

	t.Run("HasErrors method", func(t *testing.T) {
		// Test with no errors
		emptyErr := NewAggregatedValidationError([]ValidationError{})
		assert.False(t, emptyErr.HasErrors())

		// Test with errors
		withErr := NewAggregatedValidationError([]ValidationError{
			*NewValidationError("path", "error"),
		})
		assert.True(t, withErr.HasErrors())
	})
}
