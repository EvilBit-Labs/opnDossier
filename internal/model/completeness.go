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

// validateFilePath checks that the provided file path is safe, does not contain unsafe path traversal, resolves to an absolute path, and points to an existing regular file. Returns an error if validation fails.
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

// CheckModelCompleteness verifies that all fields present in the specified XML file are represented in the Go data model.
// It validates the file path, parses the XML with strict charset restrictions, extracts all XML element paths, and compares them against the model's expected paths.
// Returns an error if any XML fields are missing from the model.
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
	modelPaths := getModelPaths(reflect.TypeOf(OpnSenseDocument{}), "")

	// Find missing paths (XML paths not in our model)
	missingPaths := findMissingPaths(strippedXMLPaths, modelPaths)

	if len(missingPaths) > 0 {
		return fmt.Errorf("%w: %s: %d missing fields", ErrIncompleteModel, filePath, len(missingPaths))
	}

	return nil
}

// GetModelCompletenessDetails analyzes an XML file and the Go model to report detailed coverage information.
// It returns all XML element paths found in the file, all expected model paths derived from the Go struct, and a list of XML paths not represented in the model.
// The function validates the file path, enforces strict ASCII charset parsing, and compares the XML structure to the model for completeness.
// Returns an error if the file path is invalid or the XML cannot be read or parsed.
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

// getAllXMLPaths returns all hierarchical XML element paths found in a nested map, using dot-separated notation.
// It recursively traverses the map structure to collect every unique path.
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

// getModelPaths returns all expected XML element and attribute paths represented by a Go struct type.
// It recursively traverses the struct, interpreting XML tags (including wildcards, attributes, and nested elements) to build a set of dot-separated paths that describe the model's structure.
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

		// Handle complex XML tags like "apikeys>item"
		if strings.Contains(xmlName, ">") {
			parts := strings.Split(xmlName, ">")
			if len(parts) == 2 {
				containerName := parts[0]
				childName := parts[1]

				// Add the container path
				containerPath := containerName
				if prefix != "" {
					containerPath = prefix + "." + containerName
				}
				paths[containerPath] = true

				// Add the child path
				childPath := containerPath + "." + childName
				paths[childPath] = true

				// For slices, process the element type with the child path
				if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Array {
					elementType := field.Type.Elem()
					nestedPaths := getModelPaths(elementType, childPath)
					for path := range nestedPaths {
						paths[path] = true
					}
				}

				continue
			}
		}

		currentPath := xmlName
		if prefix != "" {
			currentPath = prefix + "." + xmlName
		}

		paths[currentPath] = true

		// Also add version and UUID attributes if they exist at the top level
		if strings.Contains(xmlTag, "version,attr") {
			paths[currentPath+".-version"] = true
		}
		if strings.Contains(xmlTag, "uuid,attr") {
			paths[currentPath+".-uuid"] = true
		}

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

		// For struct fields, also add the individual field paths
		// This handles cases where we have a struct like Widgets with nested fields
		if field.Type.Kind() == reflect.Struct {
			// Add paths for each field in the nested struct
			for i := 0; i < field.Type.NumField(); i++ {
				nestedField := field.Type.Field(i)
				nestedXMLTag := nestedField.Tag.Get("xml")
				if nestedXMLTag != "" && nestedXMLTag != "-" {
					nestedXMLName := strings.Split(nestedXMLTag, ",")[0]
					if nestedXMLName != "" {
						nestedPath := currentPath + "." + nestedXMLName
						paths[nestedPath] = true

						// Also add version and UUID attributes if they exist
						if strings.Contains(nestedXMLTag, "version,attr") {
							paths[nestedPath+".-version"] = true
						}
						if strings.Contains(nestedXMLTag, "uuid,attr") {
							paths[nestedPath+".-uuid"] = true
						}
					}
				}
			}
		}
	}

	return paths
}

// findMissingPaths returns a list of XML element paths that are not represented in the provided model paths.
// It accounts for wildcard patterns, attribute suffix variations (such as version and UUID), and attempts to reconcile differences in attribute path formats between XML parsing and model representation. Paths are considered missing if they do not match any model path, including wildcards and alternative attribute formats.
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

			// Check for various path formats that might be equivalent
			if !matched {
				// Check if the path without version attributes exists
				if strings.Contains(path, ".-version") {
					basePath := strings.ReplaceAll(path, ".-version", "")
					if modelPaths[basePath] {
						matched = true
					}
				}

				// Check if the path without UUID attributes exists
				if strings.Contains(path, ".-uuid") {
					basePath := strings.ReplaceAll(path, ".-uuid", "")
					if modelPaths[basePath] {
						matched = true
					}
				}

				// Check for XML parser vs model attribute path differences
				// XML parser: element.-attribute
				// Model: element.attribute.-attribute
				if strings.Contains(path, ".-uuid") {
					// Try converting from XML parser format to model format
					parts := strings.Split(path, ".")
					if len(parts) >= 2 {
						lastPart := parts[len(parts)-1]
						if lastPart == "-uuid" {
							// Convert element.-uuid to element.uuid.-uuid
							modelPath := strings.Join(parts[:len(parts)-1], ".") + ".uuid.-uuid"
							if modelPaths[modelPath] {
								matched = true
							}
							// Also try without the attribute suffix
							basePath := strings.Join(parts[:len(parts)-1], ".") + ".uuid"
							if modelPaths[basePath] {
								matched = true
							}
						}
					}
				}

				if strings.Contains(path, ".-version") {
					// Try converting from XML parser format to model format
					parts := strings.Split(path, ".")
					if len(parts) >= 2 {
						lastPart := parts[len(parts)-1]
						if lastPart == "-version" {
							// Convert element.-version to element.version.-version
							modelPath := strings.Join(parts[:len(parts)-1], ".") + ".version.-version"
							if modelPaths[modelPath] {
								matched = true
							}
							// Also try without the attribute suffix
							basePath := strings.Join(parts[:len(parts)-1], ".") + ".version"
							if modelPaths[basePath] {
								matched = true
							}
						}
					}
				}

				// Check for parent path existence (for nested structs)
				// Only do this if we haven't already matched the path
				if !matched {
					pathParts := strings.Split(path, ".")
					if len(pathParts) > 1 {
						// Check if any parent path exists
						for i := 1; i < len(pathParts); i++ {
							parentPath := strings.Join(pathParts[:i], ".")
							if modelPaths[parentPath] {
								// Parent exists, this is likely a valid nested field
								// Keep it as missing for implementation
								matched = false
								break
							}
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
