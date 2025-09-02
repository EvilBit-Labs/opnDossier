# Implementation Plan

## Overview

This implementation plan transforms the opnDossier CLI tool requirements and v2.0 architecture design into a series of discrete, manageable coding tasks. The plan prioritizes programmatic generation, plugin-based compliance architecture, and multi-mode audit reporting while maintaining the tool's core offline-first, security-focused principles.

## Implementation Tasks

### 1. Core Infrastructure and Architecture Foundation

- [ ] 1.1 Establish v2.0 programmatic generation architecture

  - Create `internal/markdown/generator.go` with MarkdownBuilder interface
  - Implement SecurityAssessor, DataTransformer, and StringFormatter components
  - Create optimized string building with pre-allocated buffers and sync.Pool
  - Add compile-time type safety for all generation operations
  - _Requirements: 6.1, 8.1_

- [ ] 1.2 Implement enhanced CLI command structure

  - Refactor CLI commands (convert, display, audit) with Cobra framework
  - Integrate charmbracelet/fang for styled help, errors, and automatic features
  - Add comprehensive help system with usage examples and workflow guidance
  - Implement verbose/quiet output modes with structured logging
  - _Requirements: 5.1, 5.2, 5.3_

- [ ] 1.3 Create configuration management system

  - Implement Viper-based configuration with YAML file support
  - Add environment variable support with OPNDOSSIER\_ prefix
  - Establish precedence handling (CLI flags > env vars > config file > defaults)
  - Create configuration validation and error handling
  - _Requirements: 5.2, 5.4_

### 2. XML Processing and Data Model Enhancement

- [ ] 2.1 Implement streaming XML parser with validation

  - Create XMLParser interface with streaming processing for large files
  - Add OPNsense schema validation with meaningful error messages
  - Implement contextual error reporting with line/column information
  - Add support for multiple OPNsense versions with backward compatibility
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 2.2 Enhance data model with enrichment capabilities

  - Extend OpnSenseDocument with calculated fields and derived data
  - Implement ConfigStatistics and SecurityAnalysis structures
  - Create CompletionStatus tracking for configuration coverage
  - Add data transformation utilities for processing optimization
  - _Requirements: 1.4, 2.1, 2.2_

- [ ] 2.3 Create comprehensive data validation system

  - Implement input validation for all user inputs and file paths
  - Add XML structure validation against OPNsense schema requirements
  - Create output directory validation and permission checks
  - Implement secure error messages that don't expose sensitive information
  - _Requirements: 1.5, 6.1, 6.3_

### 3. Programmatic Generation Engine Implementation

- [ ] 3.1 Build high-performance MarkdownBuilder core

  - Implement BuildStandardReport, BuildAuditReport methods
  - Create BuildSystemSection, BuildNetworkSection, BuildSecuritySection methods
  - Add optimized string building with 78% memory reduction target
  - Implement type-safe generation with compile-time validation
  - _Requirements: 2.1, 2.2, 8.1, 8.5_

- [ ] 3.2 Implement security assessment and analysis components

  - Create CalculateSecurityScore and AssessRiskLevel methods
  - Add AssessServiceRisk and DetermineSecurityZone functionality
  - Implement security finding classification and severity rating
  - Create attack surface analysis for red team mode support
  - _Requirements: 3.2, 3.3, 3.4_

- [ ] 3.3 Create data transformation and formatting utilities

  - Implement FilterSystemTunables and GroupServicesByStatus methods
  - Add FormatSystemStats and FormatTimestamp utilities
  - Create EscapeMarkdownSpecialChars and TruncateDescription functions
  - Implement FormatBoolean and other type-safe formatting methods
  - _Requirements: 2.2, 8.4, 8.5_

### 4. Multi-Mode Audit System Development

- [ ] 4.1 Implement audit mode controller and finding structures

  - Create Finding struct with Title, Severity, Description, Recommendation, Tags
  - Add red team specific fields (AttackSurface, ExploitNotes)
  - Add blue team specific fields (ComplianceRefs, Remediation)
  - Implement mode-based report generation (standard/blue/red)
  - _Requirements: 3.1, 3.2, 3.3, 3.5_

- [ ] 4.2 Build plugin-based compliance architecture

  - Create CompliancePlugin interface with standardized methods
  - Implement PluginRegistry for dynamic registration and lifecycle management
  - Add PluginManager for high-level plugin operations and statistics
  - Create plugin metadata tracking and configuration support
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [ ] 4.3 Develop compliance plugin implementations

  - Create STIG compliance plugin with control definitions and checks
  - Implement SANS framework plugin with security best practices
  - Add CIS compliance plugin with benchmark controls
  - Create plugin development documentation and examples
  - _Requirements: 4.1, 4.2, 4.5_

### 5. Multi-Format Output System

- [ ] 5.1 Implement terminal display with theme support

  - Create DisplayRenderer with Charm Glamour integration
  - Add theme detection and support (light, dark, custom)
  - Implement syntax highlighting and styled terminal output
  - Add pagination support for large configurations
  - _Requirements: 2.3, 2.4, 7.1_

- [ ] 5.2 Create multi-format file export system

  - Implement ExportMarkdown with valid, parseable output
  - Add ExportJSON and ExportYAML with format validation
  - Create smart file naming and overwrite protection
  - Implement export validation tests with standard tools
  - _Requirements: 2.1, 2.5, 5.5_

- [ ] 5.3 Add export validation and error handling

  - Create comprehensive file I/O error handling
  - Implement output format validation (markdown linters, JSON/YAML parsers)
  - Add path validation and permission checks
  - Create clear error messages for export failures
  - _Requirements: 2.5, 5.5, 6.4_

### 6. Template System and User Extensibility

- [ ] 6.1 Implement template-driven report generation

  - Create Go text/template system for user-extensible reports
  - Add template sections for interfaces, firewall rules, NAT, DHCP, certificates, VPN, routes, HA
  - Implement template directory override support for customization
  - Create template validation and error handling
  - _Requirements: 8.1, 8.2, 8.3, 8.4_

- [ ] 6.2 Create hybrid generation system for backward compatibility

  - Implement template and programmatic generation modes
  - Add migration support from template-based to programmatic generation
  - Create output comparison and validation between modes
  - Implement fallback mechanisms for template compatibility
  - _Requirements: 8.5_

### 7. Performance Optimization and Concurrent Processing

- [ ] 7.1 Implement memory-efficient processing

  - Add streaming XML processing for large files with linear memory scaling
  - Implement concurrent processing with goroutines and channels
  - Create memory usage monitoring and optimization
  - Add performance profiling capabilities with go tool pprof integration
  - _Requirements: 7.2, 7.3, 7.4_

- [ ] 7.2 Create performance benchmarking system

  - Implement benchmark tests for critical code paths
  - Add performance regression detection in CI/CD
  - Create memory allocation tracking and optimization
  - Implement throughput measurement and reporting
  - _Requirements: 7.1, 7.4, 7.5_

### 8. Security and Offline Operation

- [ ] 8.1 Implement comprehensive security controls

  - Add input validation for all user inputs with sanitization
  - Implement secure file handling with proper permissions
  - Create secure error messages without sensitive data exposure
  - Add resource usage monitoring and limits
  - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] 8.2 Ensure complete offline operation

  - Verify zero external dependencies and network calls
  - Implement portable data exchange with file-based import/export
  - Add airgap compatibility testing and validation
  - Create secure configuration management for sensitive options
  - _Requirements: 6.1, 6.5_

### 9. Cross-Platform Support and Quality Assurance

- [ ] 9.1 Implement cross-platform compatibility

  - Create static compilation with CGO_ENABLED=0
  - Add multi-platform build support (Linux, macOS, Windows)
  - Implement architecture support (amd64, arm64, 386)
  - Create native package formats and distribution
  - _Requirements: 7.4, 7.6_

- [ ] 9.2 Establish comprehensive testing framework

  - Implement unit tests with >80% coverage target
  - Create integration tests for end-to-end workflows
  - Add performance tests with benchmark regression detection
  - Implement security boundary testing and validation
  - _Requirements: 7.1, 7.5, 7.7_

### 10. Documentation and User Experience

- [ ] 10.1 Create comprehensive documentation system

  - Update README with v2.0 architecture and features
  - Create user guide with installation and usage instructions
  - Add API documentation for public interfaces
  - Create plugin development guide and examples
  - _Requirements: 5.1, 5.3_

- [ ] 10.2 Implement advanced CLI features

  - Add progress indicators for long-running operations
  - Implement tab completion support for commands and options
  - Create CLI self-validation and health check commands
  - Add about flag with project information and version details
  - _Requirements: 5.1, 5.3_

## Task Dependencies and Sequencing

### Phase 1: Foundation (Tasks 1.1-1.3)

- Establish core architecture and CLI framework
- Set up configuration management and infrastructure

### Phase 2: Core Processing (Tasks 2.1-2.3)

- Depends on Phase 1 completion
- Build XML processing and data model foundation

### Phase 3: Generation Engine (Tasks 3.1-3.3)

- Depends on Phase 2 completion
- Implement programmatic generation core

### Phase 4: Audit System (Tasks 4.1-4.3)

- Depends on Phase 3 completion
- Build multi-mode audit and plugin architecture

### Phase 5: Output System (Tasks 5.1-5.3)

- Can run parallel with Phase 4
- Implement display and export capabilities

### Phase 6: Advanced Features (Tasks 6.1-10.2)

- Depends on Phases 3-5 completion
- Add template system, performance optimization, and polish

## Success Criteria

- All tasks completed with passing tests and >80% coverage
- Performance targets met (74% faster generation, 78% memory reduction)
- Security requirements validated (offline operation, input validation)
- Cross-platform compatibility verified
- Plugin architecture functional with STIG/SANS/CIS implementations
- Multi-mode audit reporting operational (standard/blue/red)
- Complete programmatic generation system replacing template-based approach
