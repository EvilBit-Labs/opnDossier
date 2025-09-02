# Requirements Document

## Introduction

opnDossier is a specialized CLI tool designed for cybersecurity professionals to audit, analyze, and report on OPNsense firewall configurations. The tool transforms complex XML configuration files into structured, actionable reports for both defensive (blue team) and offensive (red team) security operations, supporting completely offline operation in airgapped environments.

## Requirements

### Requirement 1: Core XML Processing and Validation

**User Story:** As a network security operator, I want to parse and validate OPNsense XML configuration files, so that I can analyze firewall configurations offline with confidence in data integrity.

#### Acceptance Criteria

1. WHEN a valid OPNsense config.xml file is provided THEN the system SHALL parse the XML structure using Go's encoding/xml package
2. WHEN an invalid or malformed XML file is provided THEN the system SHALL provide specific error messages with line/column information
3. WHEN XML parsing occurs THEN the system SHALL validate the structure against OPNsense schema requirements
4. WHEN processing large configuration files THEN the system SHALL use streaming XML processing to minimize memory usage
5. WHEN XML validation fails THEN the system SHALL provide actionable error messages for quick issue resolution

### Requirement 2: Multi-Format Output Generation

**User Story:** As a security professional, I want to convert XML configurations to multiple structured formats with customizable output styles, so that I can generate documentation suitable for different audiences and use cases.

#### Acceptance Criteria

1. WHEN converting configurations THEN the system SHALL support markdown, JSON, and YAML output formats
2. WHEN generating markdown THEN the system SHALL preserve configuration hierarchy and provide comprehensive or summary output styles
3. WHEN displaying in terminal THEN the system SHALL use Charm Lipgloss for syntax highlighting with theme support (light, dark, custom)
4. WHEN exporting files THEN the system SHALL create valid, parseable files that pass standard tool validation (markdown linters, JSON parsers, YAML parsers)
5. WHEN generating output THEN the system SHALL use templates from internal/templates directory with user-extensible customization support

### Requirement 3: Advanced Audit and Compliance Reporting

**User Story:** As a cybersecurity professional, I want to generate specialized audit reports in different modes (standard, blue team, red team), so that I can perform comprehensive security analysis tailored to my operational perspective.

#### Acceptance Criteria

1. WHEN audit mode is standard THEN the system SHALL produce detailed neutral configuration documentation including system metadata, rule counts, interfaces, certificates, DHCP, routes, and high availability
2. WHEN audit mode is blue team THEN the system SHALL include audit findings (insecure SNMP, allow-all rules, expired certs), structured configuration tables, and actionable recommendations with severity ratings
3. WHEN audit mode is red team THEN the system SHALL highlight WAN-exposed services, weak NAT rules, admin portals, attack surfaces, and provide pivot data (hostnames, static leases, service ports)
4. WHEN red team mode includes blackhat commentary THEN the system SHALL provide optional attacker-focused commentary and exploit notes
5. WHEN generating audit findings THEN the system SHALL use consistent structure with Title, Severity, Description, Recommendation, Tags (Red mode adds AttackSurface, ExploitNotes)

### Requirement 4: Plugin-Based Compliance Architecture

**User Story:** As a security auditor, I want to use extensible compliance plugins for different security frameworks, so that I can perform standardized compliance checking against STIG, SANS, security benchmarks, and custom frameworks.

#### Acceptance Criteria

1. WHEN compliance plugins are loaded THEN the system SHALL support standardized interfaces with dynamic registration and lifecycle management
2. WHEN plugins are registered THEN the system SHALL track metadata, support configuration, and manage dependencies
3. WHEN compliance checks run THEN the system SHALL provide statistics reporting for both internal and external plugins
4. WHEN plugin architecture is used THEN the system SHALL support extensibility for custom compliance rules and security frameworks
5. WHEN plugins execute THEN the system SHALL integrate findings into template-driven reporting system

### Requirement 5: Comprehensive CLI Interface and Configuration Management

**User Story:** As an operator, I want an intuitive command-line interface with flexible configuration management, so that I can efficiently process configurations with customizable settings and clear feedback.

#### Acceptance Criteria

1. WHEN using the CLI THEN the system SHALL provide convert, display, and audit commands with comprehensive help documentation
2. WHEN managing configuration THEN the system SHALL support YAML files, environment variables (OPNDOSSIER\_ prefix), and CLI flag overrides with proper precedence (CLI flags > env vars > config file > defaults)
3. WHEN processing files THEN the system SHALL provide verbose and quiet output modes with progress indicators for long-running operations
4. WHEN errors occur THEN the system SHALL provide clear, actionable error messages with proper context and recovery guidance
5. WHEN exporting files THEN the system SHALL include error handling, overwrite protection, and smart file naming with user-specified paths

### Requirement 6: Security and Offline Operation

**User Story:** As a security professional working in airgapped environments, I want the tool to operate completely offline with no external dependencies, so that I can use it in high-security, isolated network environments.

#### Acceptance Criteria

1. WHEN the tool operates THEN the system SHALL function without any external dependencies or network connectivity
2. WHEN processing sensitive data THEN the system SHALL not transmit any telemetry or external communication
3. WHEN handling inputs THEN the system SHALL validate all user inputs comprehensively with secure defaults
4. WHEN managing configuration THEN the system SHALL use environment variables for sensitive options without hardcoded secrets
5. WHEN operating in restricted environments THEN the system SHALL provide portable data exchange with secure error messages that don't expose sensitive information

### Requirement 7: Cross-Platform Performance and Quality

**User Story:** As an operator across different platforms, I want high-performance, well-tested software that works consistently on Linux, macOS, and Windows, so that I can rely on it in any environment.

#### Acceptance Criteria

1. WHEN running tests THEN individual tests SHALL complete in less than 100ms with overall test coverage exceeding 80%
2. WHEN starting the CLI THEN the system SHALL start quickly for operator efficiency with memory-efficient processing
3. WHEN processing multiple operations THEN the system SHALL use concurrent processing with goroutines and channels for I/O operations
4. WHEN deployed cross-platform THEN the system SHALL work consistently across Linux, macOS, and Windows with static compilation (CGO_ENABLED=0)
5. WHEN quality checks run THEN the system SHALL pass all linting, formatting (gofmt), and security analysis (gosec) requirements

### Requirement 8: Template-Driven Report Generation

**User Story:** As a security analyst, I want customizable report templates with user-extensible sections, so that I can generate reports tailored to my organization's specific documentation and compliance requirements.

#### Acceptance Criteria

1. WHEN generating reports THEN the system SHALL use Go text/template files from internal/templates/reports/ directory
2. WHEN templates are processed THEN the system SHALL include user-extensible sections for interfaces, firewall rules, NAT rules, DHCP, certificates, VPN config, static routes, and high availability
3. WHEN custom templates are provided THEN the system SHALL support template directory overrides for user-defined customization
4. WHEN template rendering occurs THEN the system SHALL maintain backward compatibility with existing template functionality
5. WHEN programmatic generation is used THEN the system SHALL provide better performance, maintainability, consistency, and testability compared to template-only approaches
