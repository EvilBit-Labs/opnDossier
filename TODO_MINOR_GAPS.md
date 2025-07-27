# TODO Comments Added for Issue #6 Minor Gaps

## Overview

Added TODO comments to address the minor gaps (5%) identified in the GitHub issue #6 completion analysis. These comments provide clear guidance for future enhancements while documenting the current limitations.

## TODO Comments Added

### 1. Enhanced Rule Comparison (`internal/processor/analyze.go`)

**Location**: Line 107 - `rulesAreEquivalent` function
**Gap**: Current model.Rule struct is limited compared to full OPNsense rules

```go
// TODO: Enhanced Rule Comparison - Expand model.Rule struct to include:
//   - statetype (keep state, no state, etc.)
//   - direction (in, out)
//   - quick (quick rule processing)
//   - port specifications for source/destination
//   - more detailed protocol options
//   - rule flags and advanced options
// This would enable more accurate duplicate detection and dead rule analysis.
```

**Impact**: Would improve accuracy of duplicate rule detection and dead rule analysis

---

### 2. More Granular Destination Analysis (`internal/model/opnsense.go`)

**Location**: Line 496 - `Destination` struct
**Gap**: Destination model currently only supports "any" and basic network

```go
// TODO: More Granular Destination Analysis - Expand destination model to include:
//   - Port specifications (single port, port ranges, aliases)
//   - Protocol-specific destination options
//   - Network aliases and address groups
//   - IPv6 destination support
//   - Negation support (not destination)
// This would enable more comprehensive firewall rule analysis and comparison.
```

**Impact**: Would enable more comprehensive firewall rule analysis and comparison

---

### 3. Additional Service Integration (`internal/processor/analyze.go`)

**Location**: Line 151 - `analyzeUnusedInterfaces` function
**Gap**: Service usage detection limited to basic DHCP lan/wan

```go
// TODO: Additional Service Integration - Expand service usage detection to:
//   - Check all DHCP interfaces in cfg.Dhcpd.Items map (not just lan/wan)
//   - Include other services like DNS, VPN, load balancer interface usage
//   - Detect interface usage in routing, VLAN, and bridge configurations
//   - Check for interface references in monitoring and logging services
// This would provide more comprehensive unused interface detection.
```

**Impact**: Would provide more comprehensive unused interface detection across all services

---

### 4. Extended Compliance Rules (`internal/processor/example.go`)

**Location**: Line 227 - `performComplianceCheck` function
**Gap**: Limited compliance checks compared to enterprise requirements

```go
// TODO: Extended Compliance Rules - Add additional compliance checks for:
//   - Password policy enforcement (complexity, expiration)
//   - Audit logging configuration requirements
//   - Certificate management and expiration monitoring
//   - Backup and disaster recovery configuration
//   - Network segmentation best practices
//   - Security framework compliance (CIS, NIST, etc.)
//   - Regulatory compliance requirements (PCI-DSS, HIPAA, etc.)
// This would provide comprehensive compliance monitoring capabilities.
```

**Impact**: Would provide comprehensive compliance monitoring for enterprise and regulatory requirements

## Implementation Priority

### High Priority (Future Issues)

1. **Enhanced Rule Comparison** - Most impactful for core functionality
2. **More Granular Destination Analysis** - Critical for comprehensive firewall analysis

### Medium Priority

3. **Additional Service Integration** - Good enhancement for completeness
4. **Extended Compliance Rules** - Valuable for enterprise deployments

## Benefits of Adding TODOs

✅ **Documentation**: Clear guidance for future development
✅ **Maintainability**: Shows known limitations and enhancement opportunities
✅ **Planning**: Helps prioritize future development work
✅ **Contributor Guidance**: Provides clear areas where contributions are needed
✅ **Issue Tracking**: Can be converted to individual GitHub issues when ready

## Next Steps

1. **Create Separate Issues**: Convert high-priority TODOs to individual GitHub issues
2. **Assign Priorities**: Label issues based on impact and effort required
3. **Community Input**: Gather feedback on which enhancements are most valuable
4. **Implementation Planning**: Break down complex TODOs into smaller, manageable tasks

---

**Generated**: 2025-07-27
**Total TODOs Added**: 4
**Files Modified**: 3
**Build Status**: ✅ All code compiles successfully
