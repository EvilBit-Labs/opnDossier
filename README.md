# opnFocus

## Introduction

`opnFocus` is a powerful tool developed in Golang, designed to generate meaningful output from your OPNsense configuration file. Inspired by the well-regarded `TKCERT/pfFocus`, opnFocus aims to provide a similar utility for the OPNsense community, enriching the experience and management of OPNsense configurations. This project is licensed under GPL-3.0.

## Features

- **Configuration Analysis:** Parse and analyze your OPNsense configuration files to extract vital information.
- **Insightful Summaries:** Get summaries of your firewall rules, NAT port forwards, aliases, and more.
- **Security Audits:** Perform basic security checks to identify potential vulnerabilities or misconfigurations.
- **Export Options:** Export your analyzed data into various formats for further analysis or documentation purposes.

## Installation

To install opnFocus, ensure you have Golang installed on your system. Follow these steps:

```bash
# Clone the repository
git clone https://github.com/unclesp1d3r/opnFocus.git

# Navigate to the project directory
cd opnFocus

# Build the project
go build
```

# Alternatively, you can install it directly

```bash
go install
```

## Usage

To use opnFocus, run the following command:

```bash
./opnFocus <path-to-your-OPNsense-configuration-file>
```

For more detailed usage instructions, including the list of available options, run:

```bash
./opnFocus -h
```

## Contributing

We welcome contributions! If you would like to help make opnFocus better, please follow our contributing guidelines:

1. Fork the repository.
2. Create a new branch for your feature or fix.
3. Commit your changes.
4. Push to the branch.
5. Submit a pull request.
   Please ensure your code adheres to the project's coding standards and include tests, if applicable.

## License

opnFocus is licensed under the GNU General Public License v3.0. For more information, please see the LICENSE file.

## Support

If you need help or have any questions, please open an issue in the GitHub issue tracker for this project.

## Acknowledgements

A special thanks to TKCERT/pfFocus for the inspiration behind opnFocus. Check out their project [here](https://github.com/TKCERT/pfFocus).
