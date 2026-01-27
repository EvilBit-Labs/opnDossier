// Package templates provides helper functions for template-based markdown generation.
package templates

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/EvilBit-Labs/opnDossier/internal/converter/formatters"
	"github.com/EvilBit-Labs/opnDossier/internal/model"
	"github.com/Masterminds/sprig/v3"
)

// CreateTemplateFuncMap creates a function map with sprig functions and custom template functions.
func CreateTemplateFuncMap() template.FuncMap {
	funcMap := sprig.FuncMap()

	funcMap["isLast"] = isLastInSlice
	funcMap["escapeTableContent"] = formatters.EscapeTableContent
	funcMap["getSTIGDescription"] = getSTIGDescription
	funcMap["getSANSDescription"] = getSANSDescription
	funcMap["getSecurityZone"] = getSecurityZone
	funcMap["getPortDescription"] = getPortDescription
	funcMap["getProtocolDescription"] = getProtocolDescription
	funcMap["getRiskLevel"] = formatters.AssessRiskLevel
	funcMap["getRuleCompliance"] = getRuleCompliance
	funcMap["getNATRiskLevel"] = getNATRiskLevel
	funcMap["getNATRecommendation"] = getNATRecommendation
	funcMap["getCertSecurityStatus"] = getCertSecurityStatus
	funcMap["getDHCPSecurity"] = getDHCPSecurity
	funcMap["getRouteSecurityZone"] = getRouteSecurityZone
	funcMap["filterTunables"] = filterTunables
	funcMap["truncateDescription"] = truncateDescription
	funcMap["getPowerModeDescription"] = formatters.GetPowerModeDescription
	funcMap["isTruthy"] = formatters.IsTruthy
	funcMap["formatBoolean"] = formatters.FormatBooleanCheckbox
	funcMap["formatBooleanWithUnset"] = formatters.FormatBooleanWithUnset
	funcMap["formatUnixTimestamp"] = formatters.FormatUnixTimestamp
	funcMap["formatInterfacesAsLinks"] = formatters.FormatInterfacesAsLinks

	return funcMap
}

// BuildTemplatePaths builds a list of possible template paths including custom and default locations.
func BuildTemplatePaths(templateDir string) []string {
	var possiblePaths []string

	if templateDir != "" {
		possiblePaths = append(possiblePaths,
			filepath.Join(templateDir, "*.tmpl"),
			filepath.Join(templateDir, "reports", "*.tmpl"),
		)
	}

	possiblePaths = append(possiblePaths,
		"internal/templates/*.tmpl",
		"internal/templates/reports/*.tmpl",
		"../../internal/templates/*.tmpl",
		"../../internal/templates/reports/*.tmpl",
		"../templates/*.tmpl",
		"../templates/reports/*.tmpl",
	)

	return possiblePaths
}

// ParseTemplatesWithEmbeddedFallback loads templates from filesystem or embedded templates.
func ParseTemplatesWithEmbeddedFallback(
	possiblePaths []string,
	funcMap template.FuncMap,
	embeddedFS fs.FS,
) (*template.Template, error) {
	templates := template.New("opndossier").Funcs(funcMap)

	loadedCount, lastErr := parseTemplatesFromFilesystem(templates, possiblePaths)
	if loadedCount == 0 {
		embeddedCount, embeddedErr := parseTemplatesFromEmbedded(templates, embeddedFS, funcMap)
		loadedCount += embeddedCount
		if embeddedErr != nil {
			lastErr = embeddedErr
		}
	}

	if loadedCount == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("no templates found in filesystem or embedded templates")
	}

	return templates, nil
}

func isLastInSlice(index, slice any) bool {
	switch s := slice.(type) {
	case map[string]any:
		return false
	case []any:
		if i, ok := index.(int); ok {
			return i == len(s)-1
		}
	}
	return false
}

func getSTIGDescription(controlID string) string {
	return fmt.Sprintf("STIG control %s description", controlID)
}

func getSANSDescription(controlID string) string {
	return fmt.Sprintf("SANS control %s description", controlID)
}

func getSecurityZone(interfaceName string) string {
	switch interfaceName {
	case "wan":
		return "Untrusted"
	case "lan":
		return "Trusted"
	case "dmz":
		return "DMZ"
	default:
		return "Unknown"
	}
}

func getPortDescription(port string) string {
	return "Port " + port
}

func getProtocolDescription(protocol string) string {
	return "Protocol " + protocol
}

func getRuleCompliance(_ any) string {
	return "Rule Compliance Check Placeholder"
}

func getNATRiskLevel(_ any) string {
	return "NAT Rule Risk Level Placeholder"
}

func getNATRecommendation(_ any) string {
	return "NAT Rule Recommendation Placeholder"
}

func getCertSecurityStatus(_ any) string {
	return "Certificate Security Status Placeholder"
}

func getDHCPSecurity(_ any) string {
	return "DHCP Security Placeholder"
}

func getRouteSecurityZone(_ any) string {
	return "Route Security Zone Placeholder"
}

func filterTunables(tunables []model.SysctlItem, includeTunables bool) []model.SysctlItem {
	if includeTunables {
		return tunables
	}

	filtered := make([]model.SysctlItem, 0)
	for _, tunable := range tunables {
		if strings.ToLower(strings.TrimSpace(tunable.Value)) != "default" {
			filtered = append(filtered, tunable)
		}
	}
	return filtered
}

func truncateDescription(description string, maxLength int) string {
	if maxLength <= 0 {
		maxLength = 80
	}

	description = strings.ReplaceAll(description, "\n", " ")
	description = strings.ReplaceAll(description, "\r", " ")
	description = strings.Join(strings.Fields(description), " ")

	if len(description) <= maxLength {
		return description
	}

	truncated := description[:maxLength]
	lastSpace := strings.LastIndex(truncated, " ")
	if lastSpace > maxLength/2 {
		truncated = description[:lastSpace]
	}

	return truncated + "..."
}

func parseTemplatesFromFilesystem(templates *template.Template, possiblePaths []string) (int, error) {
	loadedCount := 0
	var lastErr error

	for _, path := range possiblePaths {
		matches, err := filepath.Glob(path)
		if err != nil {
			lastErr = fmt.Errorf("failed to glob pattern %s: %w", path, err)
			continue
		}

		count, err := parseTemplateFiles(templates, matches)
		loadedCount += count
		if err != nil {
			lastErr = err
		}
	}

	return loadedCount, lastErr
}

func parseTemplatesFromEmbedded(
	templates *template.Template,
	embeddedFS fs.FS,
	funcMap template.FuncMap,
) (int, error) {
	loadedCount := 0
	var lastErr error

	embeddedPaths := []string{
		"internal/templates/*.tmpl",
		"internal/templates/reports/*.tmpl",
	}

	for _, pattern := range embeddedPaths {
		matches, err := fs.Glob(embeddedFS, pattern)
		if err != nil {
			continue
		}

		count, err := parseEmbeddedTemplates(templates, embeddedFS, funcMap, matches)
		loadedCount += count
		if err != nil {
			lastErr = err
		}
	}

	return loadedCount, lastErr
}

func parseTemplateFiles(templates *template.Template, matches []string) (int, error) {
	loadedCount := 0
	var lastErr error

	for _, match := range matches {
		templateName := filepath.Base(match)
		if templates.Lookup(templateName) != nil {
			continue
		}

		if _, err := templates.ParseFiles(match); err != nil {
			lastErr = fmt.Errorf("failed to parse template %s: %w", match, err)
			continue
		}
		loadedCount++
	}

	return loadedCount, lastErr
}

func parseEmbeddedTemplates(
	templates *template.Template,
	embeddedFS fs.FS,
	funcMap template.FuncMap,
	matches []string,
) (int, error) {
	loadedCount := 0
	var lastErr error

	for _, match := range matches {
		templateName := filepath.Base(match)
		if templates.Lookup(templateName) != nil {
			continue
		}

		content, err := fs.ReadFile(embeddedFS, match)
		if err != nil {
			lastErr = fmt.Errorf("failed to read embedded template %s: %w", match, err)
			continue
		}

		if _, err = templates.New(templateName).Funcs(funcMap).Parse(string(content)); err != nil {
			lastErr = fmt.Errorf("failed to parse embedded template %s: %w", match, err)
			continue
		}
		loadedCount++
	}

	return loadedCount, lastErr
}
