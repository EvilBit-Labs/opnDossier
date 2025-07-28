# Test Data Files

This directory contains OPNsense configuration files used for testing the parser and validation components of opnFocus.

## Contents

- **`config.xml.sample`** - Basic OPNsense configuration template
- **`sample.config.1.xml`** - Sample configuration with minimal settings
- **`sample.config.2.xml`** - Sample configuration with network settings
- **`sample.config.3.xml`** - Sample configuration with security features
- **`sample.config.4.xml`** - Sample configuration with services enabled
- **`sample.config.5.xml`** - Comprehensive sample configuration
- **`opnfocus-config.xsd`** - XML Schema Definition for validation

## Sources

These configuration files were collected from public repositories and open source projects for testing purposes. While some were generated manually, others were derived from existing sources. The `opnfocus-config.xsd` schema file was generated from these sample files and may not be comprehensive or perfect. All potentially sensitive data has been sanitized or altered to ensure privacy.

## Usage

These files are used by the test suite to validate:

- XML parsing functionality
- Configuration validation
- Data transformation processes
- Report generation

## Note

These files are for testing purposes only and do not represent actual production configurations.
