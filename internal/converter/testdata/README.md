# Test Data Documentation

This directory contains test data files used for testing the converter functionality.

## Files

### `complete.json`

Complete OPNsense configuration with all sections populated for comprehensive testing.

### `minimal.json`

Minimal OPNsense configuration with only essential fields for basic functionality testing.

### `edge_cases.json`

**IMPORTANT**: This file contains intentionally invalid test data for error handling and edge case testing.

#### Intentionally Invalid Data

The following entries are deliberate test fixtures, not accidental bad data:

- **Invalid IP Address**: `"999.999.999.999"` - Used to test IP address validation
- **Invalid Subnet**: `"999"` - Used to test subnet mask validation
- **Invalid Interface Names**: `"nonexistent0"` - Used to test interface validation
- **Invalid Enable Values**: `"2"` - Used to test boolean field validation
- **Special Characters**: Various entries contain pipes (`|`), asterisks (`*`), backticks (`` ` ``), and other special characters to test markdown escaping

These values are used to verify that the application handles malformed input gracefully and provides appropriate error messages or fallback behavior.

## Usage

Test data files are loaded by test functions using `loadTestDataFromFile()` helper function. The files are parsed as JSON and converted to `model.OpnSenseDocument` structures for testing.
