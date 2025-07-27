// Package internal provides utility functions for walking and processing node structures.
package internal

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/opnFocus/internal/model"
)

// MDNode represents a Markdown node structure.
type MDNode struct {
	Level    int
	Title    string
	Body     string
	Children []MDNode
}

// Walk transforms a decoded model.Opnsense node into a hierarchy of MDNodes.
func Walk(opnsense model.Opnsense) MDNode {
	return walkNode("OPNsense Configuration", 1, opnsense)
}

const maxHeaderLevel = 6

// walkNode recursively transforms each node into an MDNode structure.
func walkNode(title string, level int, node interface{}) MDNode {
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
	case reflect.Struct:
		for i := 0; i < nodeValue.NumField(); i++ {
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
	}

	return mdNode
}

// walkSlice handles slice types.
func walkSlice(title string, level int, slice reflect.Value) MDNode {
	mdNode := MDNode{
		Level:    level,
		Title:    strings.Repeat("#", level) + " " + title,
		Children: []MDNode{},
	}

	for i := 0; i < slice.Len(); i++ {
		item := slice.Index(i)
		itemTitle := title + " " + formatIndex(i)
		child := walkNode(itemTitle, level+1, item.Interface())
		mdNode.Children = append(mdNode.Children, child)
	}

	return mdNode
}

// walkMap handles map types.
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

// formatFieldName converts CamelCase field names to more readable format.
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

// formatIndex formats array/slice indices.
func formatIndex(i int) string {
	return "[" + strconv.Itoa(i) + "]"
}
