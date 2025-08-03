// Package internal provides utility functions for walking and processing node structures.
package internal

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/EvilBit-Labs/opnDossier/internal/model"
)

// MDNode represents a Markdown node structure used to build hierarchical document representations.
// It converts structured data into a Markdown-like format with headers and content.
type MDNode struct {
	// Level indicates the heading level (1-6) for this node in the Markdown hierarchy
	Level int
	// Title contains the formatted header text for this node (e.g., "# Section Name")
	Title string
	// Body contains the content text for this node, typically key-value pairs or descriptive text
	Body string
	// Children contains nested MDNode elements that represent subsections or related content
	Children []MDNode
}

// Walk converts an OpnSenseDocument into a hierarchical MDNode tree representing its structure as Markdown-like headers and content.
func Walk(opnsense model.OpnSenseDocument) MDNode {
	return walkNode("OPNsense Configuration", 1, opnsense)
}

const maxHeaderLevel = 6

// walkNode recursively converts a Go value into an MDNode, building a hierarchical Markdown-like structure.
// It handles structs, slices, maps, pointers, and strings, formatting field names and limiting header depth to level 6.
// Struct fields are processed recursively, with empty structs treated as enabled flags and non-empty fields added as children or body content.
func walkNode(title string, level int, node any) MDNode {
	// Limit depth to H6 (level 6)
	if level > maxHeaderLevel {
		level = maxHeaderLevel
	}

	mdNode := MDNode{
		Level:    level,
		Title:    strings.Repeat("#", level) + " " + title,
		Children: []MDNode{},
	}

	nodeValue := reflect.ValueOf(node)
	nodeType := reflect.TypeOf(node)

	// Handle pointer types
	if nodeValue.Kind() == reflect.Ptr {
		if nodeValue.IsNil() {
			return mdNode
		}

		nodeValue = nodeValue.Elem()
		nodeType = nodeType.Elem()
	}

	switch nodeValue.Kind() {
	case reflect.Ptr:
		if !nodeValue.IsNil() {
			child := walkNode(title, level+1, nodeValue.Elem().Interface())
			mdNode.Children = append(mdNode.Children, child)
		}
	case reflect.Struct:
		for i := range nodeValue.NumField() {
			field := nodeValue.Field(i)
			fieldType := nodeType.Field(i)

			// Skip unexported fields
			if !field.CanInterface() {
				continue
			}

			// Skip XML name fields
			if fieldType.Name == "XMLName" {
				continue
			}

			// Handle different field types
			switch field.Kind() {
			case reflect.Struct:
				// Check if it's an empty struct
				if field.NumField() == 0 {
					// This is likely a flag field (e.g., struct{}{})
					mdNode.Body += formatFieldName(fieldType.Name) + ": enabled\n"
				} else {
					childTitle := formatFieldName(fieldType.Name)
					child := walkNode(childTitle, level+1, field.Interface())
					mdNode.Children = append(mdNode.Children, child)
				}
			case reflect.Slice:
				if field.Len() > 0 {
					childTitle := formatFieldName(fieldType.Name)
					child := walkSlice(childTitle, level+1, field)
					mdNode.Children = append(mdNode.Children, child)
				}
			case reflect.Map:
				if field.Len() > 0 {
					childTitle := formatFieldName(fieldType.Name)
					child := walkMap(childTitle, level+1, field)
					mdNode.Children = append(mdNode.Children, child)
				}
			case reflect.String:
				if field.Len() > 0 {
					mdNode.Body += formatFieldName(fieldType.Name) + ": " + field.String() + "\n"
				}
			case reflect.Ptr:
				if !field.IsNil() {
					childTitle := formatFieldName(fieldType.Name)
					child := walkNode(childTitle, level+1, field.Interface())
					mdNode.Children = append(mdNode.Children, child)
				}
			case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
				reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
				reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
				// Handle other types as needed or ignore
			}
		}
	case reflect.Slice:
		return walkSlice(title, level, nodeValue)
	case reflect.Map:
		return walkMap(title, level, nodeValue)
	case reflect.String:
		if nodeValue.Len() > 0 {
			mdNode.Body = nodeValue.String()
		}
	case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
		// Handle other types as needed or ignore
	}

	return mdNode
}

// walkSlice creates an MDNode for a slice, generating child nodes for each element with indexed titles.
func walkSlice(title string, level int, slice reflect.Value) MDNode {
	mdNode := MDNode{
		Level:    level,
		Title:    strings.Repeat("#", level) + " " + title,
		Children: []MDNode{},
	}

	for i := range slice.Len() {
		item := slice.Index(i)
		itemTitle := title + " " + formatIndex(i)
		child := walkNode(itemTitle, level+1, item.Interface())
		mdNode.Children = append(mdNode.Children, child)
	}

	return mdNode
}

// walkMap converts a map value into an MDNode, creating a child node for each key-value pair with the key as the title and recursively processing the value.
func walkMap(title string, level int, m reflect.Value) MDNode {
	mdNode := MDNode{
		Level:    level,
		Title:    strings.Repeat("#", level) + " " + title,
		Children: []MDNode{},
	}

	for _, key := range m.MapKeys() {
		value := m.MapIndex(key)
		keyStr := key.String()
		child := walkNode(keyStr, level+1, value.Interface())
		mdNode.Children = append(mdNode.Children, child)
	}

	return mdNode
}

// formatFieldName returns the input CamelCase string as a space-separated phrase, preserving acronyms.
func formatFieldName(name string) string {
	// Simple camelCase to space-separated conversion
	result := ""

	for i, r := range name {
		// Add space before uppercase letters, but not at the beginning
		// and not if the previous character was also uppercase (to handle acronyms)
		if i > 0 && r >= 'A' && r <= 'Z' {
			prevRune := rune(name[i-1])
			if prevRune < 'A' || prevRune > 'Z' {
				result += " "
			}
		}

		result += string(r)
	}

	return result
}

// formatIndex returns the given integer index formatted as a string in square brackets, e.g., "[0]".
func formatIndex(i int) string {
	return "[" + strconv.Itoa(i) + "]"
}
