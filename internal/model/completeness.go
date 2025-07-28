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

	// Strip the root element name from XML paths to match model paths
	// The XML has "opnsense" as root, but our model paths don't include it
	strippedXMLPaths := make(map[string]bool)
	for path := range xmlPaths {
		// Remove the "opnsense." prefix if it exists
		if strings.HasPrefix(path, "opnsense.") {
			strippedPath := strings.TrimPrefix(path, "opnsense.")
			strippedXMLPaths[strippedPath] = true
		} else if path == "opnsense" {
			// Skip the root element itself
			continue
		} else {
			strippedXMLPaths[path] = true
		}
	}

	// Get all expected paths from our Go model
	modelPaths = getModelPaths(reflect.TypeOf(OpnSenseDocument{}), "")

	// Find missing paths (XML paths not in our model)
	missingPaths = findMissingPaths(strippedXMLPaths, modelPaths)

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

		// Handle xml:",any" tags - these can accept any element name
		if xmlTag == ",any" {
			// For map types with ",any", we can't predict the specific names
			// but we know the structure can handle any element name
			// We'll add a wildcard path to indicate this
			currentPath := "*"
			if prefix != "" {
				currentPath = prefix + ".*"
			}
			paths[currentPath] = true

			// Also add the field name as a potential path
			fieldPath := field.Name
			if prefix != "" {
				fieldPath = prefix + "." + field.Name
			}
			paths[fieldPath] = true

			// Recursively process the map value type
			if field.Type.Kind() == reflect.Map {
				// For map[string]Interface, process the Interface type
				valueType := field.Type.Elem()
				nestedPaths := getModelPaths(valueType, currentPath)
				for path := range nestedPaths {
					paths[path] = true
				}
			}
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

		// Recursively process nested structs, pointers, and slices
		if field.Type.Kind() == reflect.Struct || field.Type.Kind() == reflect.Ptr {
			nestedPaths := getModelPaths(field.Type, currentPath)
			for path := range nestedPaths {
				paths[path] = true
			}
		} else if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Array {
			// For slices/arrays, process the element type
			elementType := field.Type.Elem()
			nestedPaths := getModelPaths(elementType, currentPath)
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
			// Check if this path matches any wildcard patterns
			matched := false
			for modelPath := range modelPaths {
				if strings.Contains(modelPath, "*") {
					// Convert wildcard pattern to regex-like matching
					pattern := strings.ReplaceAll(modelPath, "*", ".*")
					if strings.Contains(pattern, ".*") {
						// Simple wildcard matching - check if the path starts with the prefix
						prefix := strings.Split(pattern, ".*")[0]
						if strings.HasPrefix(path, prefix) {
							matched = true
							break
						}
					}
				}
			}

			if !matched {
				missingPaths = append(missingPaths, path)
			}
		}
	}

	return missingPaths
}
