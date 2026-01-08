# opnDossier v2.0 Roadmap

## Overview

This document outlines the major architectural improvements, feature enhancements, and technical debt resolution planned for opnDossier v2.0. The roadmap is based on comprehensive code analysis, identified TODO/FIXME items, and architectural improvements needed to support the project's growth.

## Core Architectural Changes

### 1. **Programmatic Markdown Generation Completion**

- **Status**: Already planned in [issue #73](https://github.com/EvilBit-Labs/opnDossier/issues/73)
- **Priority**: High
- **Description**: Complete migration from template-based to programmatic markdown generation
- **Benefits**:
  - Better performance and maintainability
  - More consistent output formatting
  - Easier testing and debugging
  - Better separation of concerns

### 2. **Deprecated Code Cleanup** 🧹

- **Priority**: High
- **Description**: Remove deprecated converter and legacy template-based code paths
- **Items to Address**:
  - `internal/converter/markdown.go` - marked as deprecated, use `markdown.Generator` instead
  - `config.GetLogLevel()` and `config.GetLogFormat()` - deprecated methods
  - Old template rendering paths after programmatic generation is complete

### 3. **Audit Mode Implementation**

- **Status**: Already planned in [Issue #26](https://github.com/EvilBit-Labs/opnDossier/issues/26) for v1.1 milestone
- **Priority**: High (but scheduled for v1.1, not v2.0)
- **Description**: Complete audit mode functionality is already well-planned in existing milestones
- **Components** (from existing Issue #26):
  - **Blue Team Mode**: Security compliance and defensive analysis
  - **Red Team Mode**: Offensive security assessment perspective
  - **Blackhat Mode**: Advanced threat modeling
  - **Plugin System**: Modular compliance plugins (STIG, SANS, CIS, etc.)
- **Note**: The TODO comments in code will be addressed as part of v1.1 milestone work
- **V2.0 Scope**: Integration improvements and architectural cleanup after v1.1 implementation

## Feature Enhancements

### 4. **Enhanced Configuration Analysis**

- **Priority**: Medium
- **Description**: Expand the analysis capabilities
- **Components**:
  - **Dead Rule Detection**: More sophisticated analysis beyond basic patterns
  - **Enhanced Model Support**: Expand `model.Rule` struct for better comparison
  - **Service Integration**: Better detection of interface usage across all services
  - **Load Balancer Support**: Currently stubbed (`internal/model/enrichment.go:398`)
- **Files with TODOs**:
  - `internal/processor/analyze.go` (lines 130, 189, 202)
  - `internal/model/enrichment.go` (line 398)

### 5. **Template System Redesign**

- **Priority**: Medium
- **Description**: Rethink template and plugin architecture
- **Goals**:
  - Simplify custom template workflow
  - Better plugin extension points
  - Cleaner separation between built-in and custom functionality
  - More intuitive user experience for customization

### 6. **Enhanced Configuration Validation & Enrichment**

- **Priority**: Medium
- **Description**: Improve configuration validation and data enrichment
- **Components**:
  - Better validation error reporting
  - Enhanced configuration enrichment pipeline
  - Smarter default detection and handling
  - Configuration precedence: CLI flags > Env vars > Config file > Defaults (Requirements F454)

### 7. **Multi-format Output Support** 📄

- **Priority**: Medium
- **Description**: Complete multi-format export capabilities beyond markdown
- **Components**:
  - JSON export (Requirements F010, F059)
  - YAML export capabilities
  - Format-specific validation and testing
  - Consistent data structure across formats
- **Alignment**: Requirements F004, F010, F015, F023

## User Experience Improvements

### 8. **CLI and UX Polish**

- **Priority**: Medium
- **Description**: Improve command-line interface and user experience
- **Components**:
  - Better progress feedback for large files
  - Improved error messages and troubleshooting
  - Enhanced section filtering and custom outputs
  - Better flag organization and help text
  - Smarter default behaviors

### 9. **Testing and Quality Assurance** 🧪

- **Priority**: High
- **Description**: Expand testing coverage and reliability
- **Components**:
  - Automated benchmarking for performance regression detection
  - Integration tests for end-to-end workflows
  - Better test fixtures and mock data
  - Performance testing for large configurations
  - Cross-platform compatibility testing

## Technical Debt and Maintenance

### 10. **Code Quality and Documentation**

- **Priority**: Medium
- **Description**: Improve code maintainability and documentation
- **Components**:
  - Update godoc documentation for all public APIs
  - Code style and lint rule enforcement
  - Better error handling patterns
  - Consistent logging practices
  - Security best practices audit

### 11. **Performance Optimization**

- **Priority**: Low-Medium
- **Description**: Optimize for better performance with large configurations
- **Components**:
  - Memory usage optimization
  - Concurrent processing improvements
  - Better streaming for large files
  - Cache optimization where appropriate

## Implementation Strategy

### Phase 1: Foundation (v2.0.0-alpha)

- Complete programmatic markdown generation (#73)
- Remove deprecated code paths
- Basic audit mode framework implementation
- Enhanced testing infrastructure

### Phase 2: Core Features (v2.0.0-beta)

- Full audit mode implementation with plugins
- Enhanced configuration analysis
- Template system redesign
- CLI/UX improvements

### Phase 3: Polish and Release (v2.0.0)

- Performance optimization
- Documentation completion
- Security audit
- Cross-platform testing
- Migration guide from v1.x

## Breaking Changes

### Expected Breaking Changes in v2.0

- Removal of deprecated `converter` package
- Changes to configuration file format for new features
- CLI flag reorganization for better UX
- Template format changes for custom templates
- API changes in public interfaces

### Migration Support

- Provide clear migration guide
- Consider compatibility shims where practical
- Document all breaking changes thoroughly
- Provide automated migration tools where possible

## Success Metrics

- [ ] 100% removal of TODO/FIXME comments related to core functionality
- [ ] Full audit mode feature parity with design specifications
- [ ] Performance improvements measurable via benchmarks
- [ ] Zero deprecated code paths in v2.0 release
- [ ] Comprehensive test coverage >85%
- [ ] Clean API design with minimal breaking changes in future releases

## Community and Contribution

### Contribution Opportunities

- Plugin development for audit modes
- Template contributions for various use cases
- Testing on different OPNsense versions
- Documentation improvements
- Performance optimization contributions

### Backwards Compatibility

- Maintain configuration file compatibility where possible
- Provide clear upgrade paths
- Support both old and new CLI patterns during transition
- Comprehensive changelog and migration documentation

---

This roadmap represents a significant evolution of opnDossier while maintaining its core mission of providing excellent OPNsense configuration analysis and documentation. The focus on completing audit modes and improving the programmatic generation will position the project for long-term success and community growth.
