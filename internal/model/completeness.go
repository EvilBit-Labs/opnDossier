//go:build completeness
// +build completeness

package model

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/clbanning/mxj"
)

var (
	// ErrFailedToReadFile is returned when a file cannot be read
	ErrFailedToReadFile = errors.New("failed to read file")
	// ErrFailedToParseXML is returned when XML cannot be parsed
	ErrFailedToParseXML = errors.New("failed to parse XML")
	// ErrIncompleteModel is returned when XML contains fields not represented in the model
	ErrIncompleteModel = errors.New("XML contains fields not represented in model")
	// ErrInvalidFilePath is returned when the filepath is invalid or contains path traversal
	ErrInvalidFilePath = errors.New("invalid filepath")
)

// validateFilePath ensures the filepath is safe and doesn't contain path traversal
func validateFilePath(filePath string) error {
	// Check for malicious path traversal attempts
	if strings.Contains(filePath, "..") && !strings.HasPrefix(filePath, "../") {
		return fmt.Errorf("%w: %s", ErrInvalidFilePath, filePath)
	}

	// Ensure the path is absolute or properly resolved
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidFilePath, filePath, err)
	}

	// Additional validation: ensure it's a regular file
	if info, err := os.Stat(absPath); err != nil || info.IsDir() {
		return fmt.Errorf("%w: %s", ErrInvalidFilePath, filePath)
	}

	return nil
}

// CheckModelCompleteness is a standalone function that can be called
// programmatically to test model completeness for a specific file
func CheckModelCompleteness(filePath string) error {
	// Validate the filepath first
	if err := validateFilePath(filePath); err != nil {
		return err
	}

	// Read the XML file
	data, err := os.ReadFile(filePath) //nolint:gosec // filePath is validated by validateFilePath
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrFailedToReadFile, filePath, err)
	}

	// Set up custom charset reader for mxj
	mxj.XmlCharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch charset {
		case "us-ascii", "ascii":
			// us-ascii is a subset of UTF-8, so we can just return the input
			return input, nil
		default:
			// For other charsets, return an error to maintain strict behavior
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedCharset, charset)
		}
	}

	// Parse XML into a map using mxj
	xmlMap, err := mxj.NewMapXml(data)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrFailedToParseXML, filePath, err)
	}

	// Get all XML paths from the map
	xmlPaths := getAllXMLPaths(xmlMap, "")

	// Get all expected paths from our Go model
	modelPaths := getModelPaths(reflect.TypeOf(OpnSenseDocument{}), "")

	// Find missing paths (XML paths not in our model)
	missingPaths := findMissingPaths(xmlPaths, modelPaths)

	if len(missingPaths) > 0 {
		return fmt.Errorf("%w: %s: %d missing fields", ErrIncompleteModel, filePath, len(missingPaths))
	}

	return nil
}

// GetModelCompletenessDetails returns detailed information about model coverage
func GetModelCompletenessDetails(filePath string) (xmlPaths, modelPaths map[string]bool, missingPaths []string, err error) {
	// Validate the filepath first
	if err := validateFilePath(filePath); err != nil {
		return nil, nil, nil, err
	}

	// Read the XML file
	data, err := os.ReadFile(filePath) //nolint:gosec // filePath is validated by validateFilePath
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %s: %v", ErrFailedToReadFile, filePath, err)
	}

	// Set up custom charset reader for mxj
	mxj.XmlCharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch charset {
		case "us-ascii", "ascii":
			// us-ascii is a subset of UTF-8, so we can just return the input
			return input, nil
		default:
			// For other charsets, return an error to maintain strict behavior
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedCharset, charset)
		}
	}

	// Parse XML into a map using mxj
	xmlMap, err := mxj.NewMapXml(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %s: %v", ErrFailedToParseXML, filePath, err)
	}

	// Get all XML paths from the map
	xmlPaths = getAllXMLPaths(xmlMap, "")

	// Get all expected paths from our Go model
	modelPaths = getModelPaths(reflect.TypeOf(OpnSenseDocument{}), "")

	// Find missing paths (XML paths not in our model)
	missingPaths = findMissingPaths(xmlPaths, modelPaths)

	return xmlPaths, modelPaths, missingPaths, nil
}

// getAllXMLPaths recursively extracts all XML paths from a map
func getAllXMLPaths(data map[string]interface{}, prefix string) map[string]bool {
	paths := make(map[string]bool)

	for key, value := range data {
		currentPath := key
		if prefix != "" {
			currentPath = prefix + "." + key
		}

		paths[currentPath] = true

		// Recursively process nested maps
		if nestedMap, ok := value.(map[string]interface{}); ok {
			nestedPaths := getAllXMLPaths(nestedMap, currentPath)
			for path := range nestedPaths {
				paths[path] = true
			}
		}
	}

	return paths
}

// getModelPaths recursively extracts all expected paths from a Go struct type
func getModelPaths(t reflect.Type, prefix string) map[string]bool {
	paths := make(map[string]bool)

	// Handle pointer types
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// Only process struct types
	if t.Kind() != reflect.Struct {
		return paths
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Get the XML tag
		xmlTag := field.Tag.Get("xml")
		if xmlTag == "" || xmlTag == "-" {
			continue
		}

		// Extract the XML name from the tag
		xmlName := strings.Split(xmlTag, ",")[0]
		if xmlName == "" {
			continue
		}

		currentPath := xmlName
		if prefix != "" {
			currentPath = prefix + "." + xmlName
		}

		paths[currentPath] = true

		// Recursively process nested structs
		if field.Type.Kind() == reflect.Struct || field.Type.Kind() == reflect.Ptr {
			nestedPaths := getModelPaths(field.Type, currentPath)
			for path := range nestedPaths {
				paths[path] = true
			}
		}
	}

	return paths
}

// findMissingPaths finds XML paths that are not represented in the model
func findMissingPaths(xmlPaths, modelPaths map[string]bool) []string {
	var missingPaths []string

	for path := range xmlPaths {
		if !modelPaths[path] {
			missingPaths = append(missingPaths, path)
		}
	}

	return missingPaths
}
