# Implementation Plan

## Overview

This implementation plan transforms the opnDossier CLI tool requirements and v2.0 architecture design into a series of discrete, manageable coding tasks. Each task is designed to be executed independently by an AI coding agent, with clear objectives and specific code deliverables.

## Implementation Tasks

### 1. Core Infrastructure and Architecture Foundation

- [ ] 1.1 Create MarkdownBuilder interface and basic structure

  - Create `internal/markdown/generator.go` with MarkdownBuilder interface definition
  - Add basic struct with buffer, config, and options fields
  - Implement NewMarkdownBuilder constructor function
  - Add basic error handling and validation methods
  - _Requirements: 6.1, 8.1_

- [ ] 1.2 Implement SecurityAssessor component

  - Create `internal/markdown/security_assessor.go` with security analysis methods
  - Implement CalculateSecurityScore method for configuration scoring
  - Add AssessRiskLevel method for severity classification
  - Create AssessServiceRisk method for service-specific risk analysis
  - _Requirements: 3.2, 3.3_

- [ ] 1.3 Implement DataTransformer component

  - Create `internal/markdown/data_transformer.go` with data processing utilities
  - Add FilterSystemTunables method for system configuration filtering
  - Implement GroupServicesByStatus method for service organization
  - Create FormatSystemStats method for statistics formatting
  - _Requirements: 2.2, 8.4_

- [ ] 1.4 Implement StringFormatter component

  - Create `internal/markdown/string_formatter.go` with formatting utilities
  - Add EscapeMarkdownSpecialChars method for safe markdown output
  - Implement FormatTimestamp method for consistent time formatting
  - Create TruncateDescription and FormatBoolean utility methods
  - _Requirements: 8.4, 8.5_

- [ ] 1.5 Add optimized string building with memory pools

  - Enhance MarkdownBuilder with sync.Pool for buffer reuse
  - Implement pre-allocated buffer management for performance
  - Add memory usage tracking and optimization
  - Create buffer reset and cleanup methods
  - _Requirements: 7.2, 7.3_

### 2. CLI Command Structure Enhancement

- [ ] 2.1 Refactor convert command with enhanced CLI structure

  - Update `cmd/convert.go` to use Cobra framework best practices
  - Add comprehensive flag definitions and validation
  - Implement command execution logic with proper error handling
  - Add usage examples and help text
  - _Requirements: 5.1, 5.2_

- [ ] 2.2 Refactor display command with enhanced CLI structure

  - Update `cmd/display.go` with improved command structure
  - Add theme selection flags and validation
  - Implement display options and configuration
  - Add comprehensive help and usage examples
  - _Requirements: 5.1, 5.2_

- [ ] 2.3 Create audit command with CLI structure

  - Create `cmd/audit.go` with audit-specific command structure
  - Add mode selection flags (standard, blue, red)
  - Implement plugin selection and configuration flags
  - Add blackhat mode flag for red team commentary
  - _Requirements: 3.1, 5.1_

- [ ] 2.4 Integrate charmbracelet/fang for enhanced CLI experience

  - Update root command to use fang.Execute() for styled output
  - Configure automatic version, completion, and help features
  - Add styled error messages and user feedback
  - Implement enhanced CLI aesthetics and usability
  - _Requirements: 5.1, 5.3_

- [ ] 2.5 Implement verbose and quiet output modes

  - Add global verbose and quiet flags to root command
  - Create structured logging configuration with charmbracelet/log
  - Implement log level management based on verbosity flags
  - Add contextual logging throughout application components
  - _Requirements: 5.3_

### 3. Configuration Management System

- [ ] 3.1 Create YAML configuration file support

  - Enhance `internal/config/config.go` with Viper integration
  - Add YAML configuration file loading and parsing
  - Implement configuration validation and error handling
  - Create default configuration structure and values
  - _Requirements: 5.2, 5.4_

- [ ] 3.2 Add environment variable support

  - Implement OPNDOSSIER\_ prefixed environment variable support
  - Add environment variable binding with Viper
  - Create environment variable validation and type conversion
  - Add documentation for supported environment variables
  - _Requirements: 5.2, 5.4_

- [ ] 3.3 Establish configuration precedence handling

  - Implement precedence logic (CLI flags > env vars > config file > defaults)
  - Add configuration merging and override functionality
  - Create configuration source tracking and debugging
  - Implement configuration validation across all sources
  - _Requirements: 5.2, 5.4_

### 4. XML Processing and Data Model Enhancement

- [ ] 4.1 Implement streaming XML parser interface

  - Create XMLParser interface in `internal/parser/xml.go`
  - Add streaming XML processing for large file support
  - Implement memory-efficient parsing with io.Reader
  - Create parser configuration and options structure
  - _Requirements: 1.1, 1.4_

- [ ] 4.2 Add OPNsense schema validation

  - Implement schema validation methods in XMLParser
  - Add OPNsense version detection and compatibility checking
  - Create validation error reporting with line/column information
  - Add support for multiple OPNsense configuration versions
  - _Requirements: 1.2, 1.3_

- [ ] 4.3 Enhance OpnSenseDocument with enrichment fields

  - Add ConfigStatistics, SecurityAnalysis, and CompletionStatus fields
  - Implement JSON tags for multi-format export support
  - Create data enrichment methods for calculated fields
  - Add validation methods for enriched data structures
  - _Requirements: 1.4, 2.1, 2.2_

- [ ] 4.4 Create data enrichment engine

  - Implement `internal/model/enrichment.go` with enrichment methods
  - Add statistics calculation for configuration analysis
  - Create security analysis methods for risk assessment
  - Implement completeness tracking for configuration coverage
  - _Requirements: 2.1, 2.2_

- [ ] 4.5 Implement comprehensive input validation

  - Create input validation methods for all user inputs
  - Add file path sanitization and security checks
  - Implement XML structure validation with detailed error reporting
  - Create secure error messages without sensitive data exposure
  - _Requirements: 1.5, 6.1, 6.3_

### 5. Programmatic Generation Engine Core

- [ ] 5.1 Implement BuildStandardReport method

  - Create BuildStandardReport method in MarkdownBuilder
  - Add neutral documentation generation for standard mode
  - Implement system metadata, rule counts, and interface documentation
  - Create comprehensive configuration overview generation
  - _Requirements: 3.3, 8.1_

- [ ] 5.2 Implement BuildAuditReport method

  - Create BuildAuditReport method with mode-specific generation
  - Add audit finding integration and formatting
  - Implement mode-based content selection (standard/blue/red)
  - Create finding severity and recommendation formatting
  - _Requirements: 3.1, 3.2, 3.3_

- [ ] 5.3 Implement BuildSystemSection method

  - Create BuildSystemSection method for system configuration
  - Add hostname, domain, and system metadata formatting
  - Implement system statistics and performance metrics
  - Create system service and daemon documentation
  - _Requirements: 8.1, 8.2_

- [ ] 5.4 Implement BuildNetworkSection method

  - Create BuildNetworkSection method for network configuration
  - Add interface configuration and status documentation
  - Implement routing table and gateway information
  - Create network topology and VLAN documentation
  - _Requirements: 8.1, 8.2_

- [ ] 5.5 Implement BuildSecuritySection method

  - Create BuildSecuritySection method for security configuration
  - Add firewall rules and NAT configuration documentation
  - Implement certificate and VPN configuration details
  - Create security policy and access control documentation
  - _Requirements: 3.2, 8.1, 8.2_

### 6. Multi-Mode Audit System Development

- [ ] 6.1 Create Finding data structure

  - Implement Finding struct with Title, Severity, Description, Recommendation, Tags
  - Add red team specific fields (AttackSurface, ExploitNotes)
  - Add blue team specific fields (ComplianceRefs, Remediation)
  - Create finding validation and serialization methods
  - _Requirements: 3.1, 3.5_

- [ ] 6.2 Implement audit mode controller

  - Create `internal/audit/mode_controller.go` with mode management
  - Add mode-based report generation logic (standard/blue/red)
  - Implement mode validation and configuration
  - Create mode-specific content filtering and formatting
  - _Requirements: 3.1, 3.2, 3.3_

- [ ] 6.3 Create CompliancePlugin interface

  - Define CompliancePlugin interface in `internal/plugin/interfaces.go`
  - Add plugin lifecycle methods (Name, Version, Check, Configure)
  - Implement PluginMetadata structure for plugin information
  - Create plugin validation and error handling
  - _Requirements: 4.1, 4.2_

- [ ] 6.4 Implement PluginRegistry for dynamic registration

  - Create PluginRegistry in `internal/audit/plugin.go`
  - Add dynamic plugin registration and discovery
  - Implement plugin lifecycle management and validation
  - Create plugin dependency tracking and resolution
  - _Requirements: 4.2, 4.3_

- [ ] 6.5 Create PluginManager for high-level operations

  - Implement PluginManager in `internal/audit/plugin_manager.go`
  - Add plugin execution orchestration and statistics
  - Create plugin configuration management and validation
  - Implement plugin error handling and recovery
  - _Requirements: 4.3, 4.4_

### 7. Compliance Plugin Implementations

- [ ] 7.1 Create STIG compliance plugin

  - Implement STIG plugin in `internal/plugins/stig/stig.go`
  - Add STIG control definitions and validation rules
  - Create STIG-specific finding generation and reporting
  - Implement STIG compliance scoring and assessment
  - _Requirements: 4.1, 4.5_

- [ ] 7.2 Create SANS compliance plugin

  - Implement SANS plugin in `internal/plugins/sans/sans.go`
  - Add SANS framework controls and best practices
  - Create SANS-specific security analysis and recommendations
  - Implement SANS compliance reporting and scoring
  - _Requirements: 4.1, 4.5_

- [ ] 7.3 Create security benchmark compliance plugin

  - Implement security benchmark plugin in `internal/plugins/benchmark/benchmark.go`
  - Add security benchmark controls and validation rules inspired by industry standards
  - Create benchmark-specific finding generation and assessment
  - Implement security benchmark compliance scoring and reporting
  - _Requirements: 4.1, 4.5_

### 8. Multi-Format Output System

- [ ] 8.1 Implement terminal display with theme support

  - Enhance `internal/display/display.go` with Charm Glamour integration
  - Add theme detection and support (light, dark, custom)
  - Implement syntax highlighting and styled terminal output
  - Create pagination support for large configurations
  - _Requirements: 2.3, 2.4, 7.1_

- [ ] 8.2 Create markdown file export functionality

  - Implement ExportMarkdown method in `internal/export/file.go`
  - Add valid, parseable markdown output generation
  - Create smart file naming and overwrite protection
  - Implement markdown validation with standard tools
  - _Requirements: 2.1, 2.5, 5.5_

- [ ] 8.3 Create JSON file export functionality

  - Implement ExportJSON method for structured data export
  - Add JSON validation and formatting
  - Create JSON schema validation for exported data
  - Implement JSON-specific error handling and validation
  - _Requirements: 2.1, 2.5, 5.5_

- [ ] 8.4 Create YAML file export functionality

  - Implement ExportYAML method for human-readable structured export
  - Add YAML validation and formatting
  - Create YAML-specific error handling and validation
  - Implement YAML schema validation for exported data
  - _Requirements: 2.1, 2.5, 5.5_

- [ ] 8.5 Add comprehensive export validation

  - Create export validation tests with standard tools
  - Add file format validation (markdown linters, JSON/YAML parsers)
  - Implement path validation and permission checks
  - Create clear error messages for export failures
  - _Requirements: 2.5, 5.5, 6.4_

### 9. Template System and User Extensibility

- [ ] 9.1 Create Go text/template system

  - Implement template loading and parsing in `internal/templates/`
  - Add template sections for interfaces, firewall rules, NAT, DHCP, certificates
  - Create template validation and error handling
  - Implement template variable binding and execution
  - _Requirements: 8.1, 8.2, 8.3_

- [ ] 9.2 Add template directory override support

  - Implement user template directory override functionality
  - Add template discovery and loading from custom directories
  - Create template inheritance and composition support
  - Implement template validation for user-provided templates
  - _Requirements: 8.3, 8.4_

- [ ] 9.3 Create hybrid generation system

  - Implement template and programmatic generation mode selection
  - Add backward compatibility support for existing templates
  - Create output comparison and validation between modes
  - Implement migration utilities from template to programmatic generation
  - _Requirements: 8.5_

### 10. Performance Optimization and Testing

- [ ] 10.1 Implement memory-efficient processing

  - Add streaming XML processing for large files
  - Implement concurrent processing with goroutines and channels
  - Create memory usage monitoring and optimization
  - Add performance profiling capabilities
  - _Requirements: 7.2, 7.3, 7.4_

- [ ] 10.2 Create performance benchmarking system

  - Implement benchmark tests for critical code paths
  - Add performance regression detection
  - Create memory allocation tracking and optimization
  - Implement throughput measurement and reporting
  - _Requirements: 7.1, 7.4, 7.5_

- [ ] 10.3 Implement comprehensive unit testing

  - Create unit tests for all components with >80% coverage target
  - Add table-driven tests for multiple scenarios
  - Implement mock interfaces for external dependencies
  - Create test fixtures and helper utilities
  - _Requirements: 7.1, 7.5, 7.7_

- [ ] 10.4 Create integration testing framework

  - Implement end-to-end workflow testing
  - Add cross-platform compatibility testing
  - Create security boundary testing and validation
  - Implement performance integration testing
  - _Requirements: 7.5, 7.6, 7.7_

### 11. Security and Cross-Platform Support

- [ ] 11.1 Implement comprehensive security controls

  - Add input validation for all user inputs with sanitization
  - Implement secure file handling with proper permissions
  - Create secure error messages without sensitive data exposure
  - Add resource usage monitoring and limits
  - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] 11.2 Ensure complete offline operation

  - Verify zero external dependencies and network calls
  - Implement portable data exchange with file-based import/export
  - Add airgap compatibility testing and validation
  - Create secure configuration management for sensitive options
  - _Requirements: 6.1, 6.5_

- [ ] 11.3 Implement cross-platform compatibility

  - Create static compilation with CGO_ENABLED=0
  - Add multi-platform build support (Linux, macOS, Windows)
  - Implement architecture support (amd64, arm64, 386)
  - Create native package formats and distribution
  - _Requirements: 7.4, 7.6_

### 12. Documentation and User Experience

- [ ] 12.1 Create comprehensive documentation

  - Update README with v2.0 architecture and features
  - Create user guide with installation and usage instructions
  - Add API documentation for public interfaces
  - Create plugin development guide and examples
  - _Requirements: 5.1, 5.3_

- [ ] 12.2 Implement advanced CLI features

  - Add progress indicators for long-running operations
  - Implement tab completion support for commands and options
  - Create CLI self-validation and health check commands
  - Add about flag with project information and version details
  - _Requirements: 5.1, 5.3_

## Task Dependencies and Sequencing

### Phase 1: Foundation (Tasks 1.1-3.3)

- Core architecture, CLI structure, and configuration management
- No dependencies - can start immediately

### Phase 2: Data Processing (Tasks 4.1-4.5)

- XML processing and data model enhancement
- Depends on Phase 1 completion

### Phase 3: Generation Engine (Tasks 5.1-5.5)

- Programmatic generation core implementation
- Depends on Phase 2 completion

### Phase 4: Audit System (Tasks 6.1-7.3)

- Multi-mode audit and plugin architecture
- Depends on Phase 3 completion

### Phase 5: Output System (Tasks 8.1-9.3)

- Display, export, and template systems
- Can run parallel with Phase 4

### Phase 6: Quality and Polish (Tasks 10.1-12.2)

- Performance, testing, security, and documentation
- Depends on Phases 3-5 completion

## Success Criteria

- Each task produces working, tested code with clear functionality
- All tasks pass individual unit tests and integration validation
- Performance targets met (74% faster generation, 78% memory reduction)
- Security requirements validated (offline operation, input validation)
- Cross-platform compatibility verified
- Plugin architecture functional with compliance implementations
- Multi-mode audit reporting operational (standard/blue/red)
- Complete programmatic generation system operational
