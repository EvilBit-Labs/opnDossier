// Package internal provides utility functions for walking and processing node structures.
package internal

import (
	"reflect"
	"slices"
	"strconv"
	"strings"

	common "github.com/EvilBit-Labs/opnDossier/pkg/model"
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

// Walk converts a CommonDevice into a hierarchical MDNode tree representing its
// structure as Markdown-like headers and content.
func Walk(device common.CommonDevice) MDNode {
	return walkNode("Device Configuration", 1, device)
}

// maxHeaderLevel is the deepest markdown heading level (h6) used when walking nested structs.
const maxHeaderLevel = 6

// walkNode recursively converts a Go value into an MDNode, building a hierarchical Markdown-like structure.
// It handles structs, slices, maps, pointers, and strings, formatting field names and limiting header depth to level 6.
// Struct fields are processed recursively, with empty structs and true boolean values treated as enabled flags and non-empty fields added as children or body content.
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
		walkStructFields(&mdNode, nodeValue, nodeType, level)
	case reflect.Slice:
		return walkSlice(title, level, nodeValue)
	case reflect.Map:
		return walkMap(title, level, nodeValue)
	case reflect.String:
		if nodeValue.Len() > 0 {
			mdNode.Body = nodeValue.String()
		}
	case reflect.Bool:
		if nodeValue.Bool() {
			mdNode.Body = "enabled"
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if nodeValue.Int() != 0 {
			mdNode.Body = strconv.FormatInt(nodeValue.Int(), 10)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if nodeValue.Uint() != 0 {
			mdNode.Body = strconv.FormatUint(nodeValue.Uint(), 10)
		}
	case reflect.Invalid, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
		// Handle other types as needed or ignore
	}

	return mdNode
}

// walkStructFields dispatches each exported, non-XMLName field of nodeValue
// to the kind-appropriate handler (see walkStructField*). Extracted from
// walkNode so each level of the reflection walk is readable on its own.
func walkStructFields(mdNode *MDNode, nodeValue reflect.Value, nodeType reflect.Type, level int) {
	for i := range nodeValue.NumField() {
		field := nodeValue.Field(i)
		fieldType := nodeType.Field(i)
		if !field.CanInterface() || fieldType.Name == "XMLName" {
			continue
		}
		walkStructField(mdNode, fieldType, field, level)
	}
}

// walkStructField applies the kind-specific rendering for one struct field.
func walkStructField(mdNode *MDNode, fieldType reflect.StructField, field reflect.Value, level int) {
	switch field.Kind() {
	case reflect.Struct:
		if field.NumField() == 0 {
			// Empty struct (struct{}{}) is treated as a flag.
			mdNode.Body += formatFieldName(fieldType.Name) + ": enabled\n"
			return
		}
		mdNode.Children = append(mdNode.Children,
			walkNode(formatFieldName(fieldType.Name), level+1, field.Interface()))
	case reflect.Slice:
		if field.Len() > 0 {
			mdNode.Children = append(mdNode.Children,
				walkSlice(formatFieldName(fieldType.Name), level+1, field))
		}
	case reflect.Map:
		if field.Len() > 0 {
			mdNode.Children = append(mdNode.Children,
				walkMap(formatFieldName(fieldType.Name), level+1, field))
		}
	case reflect.String:
		if field.Len() > 0 {
			mdNode.Body += formatFieldName(fieldType.Name) + ": " + field.String() + "\n"
		}
	case reflect.Ptr:
		if !field.IsNil() {
			mdNode.Children = append(mdNode.Children,
				walkNode(formatFieldName(fieldType.Name), level+1, field.Interface()))
		}
	case reflect.Bool:
		if field.Bool() {
			mdNode.Body += formatFieldName(fieldType.Name) + ": enabled\n"
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() != 0 {
			mdNode.Body += formatFieldName(fieldType.Name) + ": " + strconv.FormatInt(field.Int(), 10) + "\n"
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if field.Uint() != 0 {
			mdNode.Body += formatFieldName(fieldType.Name) + ": " + strconv.FormatUint(field.Uint(), 10) + "\n"
		}
	case reflect.Invalid, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.UnsafePointer:
		// Handle other types as needed or ignore
	}
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

// walkMap converts a map value into an MDNode, iterating over keys in sorted
// lexicographic order and creating a child node for each key-value pair.
func walkMap(title string, level int, m reflect.Value) MDNode {
	mdNode := MDNode{
		Level:    level,
		Title:    strings.Repeat("#", level) + " " + title,
		Children: []MDNode{},
	}

	keys := m.MapKeys()
	slices.SortFunc(keys, func(a, b reflect.Value) int {
		return strings.Compare(a.String(), b.String())
	})

	for _, key := range keys {
		value := m.MapIndex(key)
		keyStr := key.String()
		child := walkNode(keyStr, level+1, value.Interface())
		mdNode.Children = append(mdNode.Children, child)
	}

	return mdNode
}

// formatFieldName returns the input CamelCase string as a space-separated phrase, preserving acronyms.
func formatFieldName(name string) string {
	var b strings.Builder

	for i, r := range name {
		// Add space before uppercase letters, but not at the beginning
		// and not if the previous character was also uppercase (to handle acronyms)
		if i > 0 && r >= 'A' && r <= 'Z' {
			prevRune := rune(name[i-1])
			if prevRune < 'A' || prevRune > 'Z' {
				b.WriteString(" ")
			}
		}

		b.WriteRune(r)
	}

	return b.String()
}

// formatIndex returns the given integer index formatted as a string in square brackets, e.g., "[0]".
func formatIndex(i int) string {
	return "[" + strconv.Itoa(i) + "]"
}
