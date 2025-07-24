# Parser Test Data

This directory contains sample OPNsense configuration files used for testing the XML parser.

## Files

- `config.xml.sample` - Main sample configuration file used for comprehensive testing (borrowed from OPNsense)
- `config-minimal.xml.sample` - Example minimal configuration for demonstration

## Adding New Test Samples

To add additional sample configuration files for testing:

1. **Add your XML file** to this directory with a `.xml.sample` extension
2. **Name it descriptively**, e.g.:
   - `config-minimal.xml.sample` - for a minimal configuration
   - `config-enterprise.xml.sample` - for an enterprise setup
   - `config-vpn.xml.sample` - for a VPN-focused configuration
   - `config-loadbalancer.xml.sample` - for load balancer configurations

3. **Ensure the file is valid XML** and follows the OPNsense configuration schema

4. **Run the tests** to ensure your new sample file parses correctly:

   ```bash
   go test ./internal/parser -v
   ```

## Test Coverage

The test suite automatically discovers and tests all `.xml` files in this directory. Each sample file is:

1. **Parsed** to ensure no XML parsing errors occur
2. **Validated** for structural integrity and required fields
3. **Checked** for reasonable values in key configuration areas

## Test Categories

The tests validate:

- **Basic Structure**: Root element and overall XML structure
- **System Configuration**: Hostname, domain, users, groups
- **Network Interfaces**: WAN/LAN configuration and settings
- **Sysctl Items**: Kernel parameter configurations
- **Firewall Rules**: Filter rules and their validity
- **Load Balancer Monitors**: Monitor type configurations
- **Services**: DNS, SNMP, NAT, NTP configurations

## Performance Testing

The benchmark tests measure parsing performance using the sample files. Larger or more complex configuration files will help identify performance characteristics.

## Privacy Considerations

**Important**: Do not commit real production configuration files that may contain:

- Passwords or password hashes
- Private keys or certificates
- Internal IP addresses or network topology
- Sensitive system information

Always sanitize configuration files before adding them as test samples.
