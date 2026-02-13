# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |
| < 1.0   | :x:                |

Users on 1.0.x or earlier should upgrade to 1.2.x. There are no breaking changes between releases.

## Reporting a Vulnerability

We take the security of opnDossier seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of the following channels:

1. [GitHub Private Vulnerability Reporting](https://github.com/EvilBit-Labs/opnDossier/security/advisories/new) (preferred)
2. Email [support@evilbitlabs.io](mailto:support@evilbitlabs.io) encrypted with our [PGP key](#pgp-key) (`F4382BC0`)

Please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Scope

**In scope:**

- Vulnerabilities in opnDossier's XML parser (e.g., XXE, billion laughs)
- Path traversal in file input/output handling
- Command injection via CLI arguments
- Information disclosure in generated reports

**Out of scope:**

- Vulnerabilities in OPNsense itself
- Issues requiring physical access to the machine running opnDossier
- Social engineering attacks

### What to expect

- We will acknowledge receipt of your report within **48 hours**
- We will provide an initial assessment within **7 days**
- We aim to release a fix within **90 days** of confirmed vulnerabilities
- We will coordinate disclosure through a [GitHub Security Advisory](https://github.com/EvilBit-Labs/opnDossier/security/advisories)
- We will credit you in the advisory (unless you prefer to remain anonymous)

### Responsible Disclosure

We ask that you:

- Give us reasonable time to respond to issues before any disclosure
- Avoid accessing or modifying other users' data
- Avoid actions that could negatively impact other users

### Security Best Practices

When using opnDossier:

- Keep your OPNsense configuration files secure
- Regularly update to the latest version
- Review generated reports for sensitive information before sharing
- Use appropriate file permissions for configuration files (0600)

## Security Features

opnDossier includes several security-focused features:

- Secure parsing of OPNsense configuration files
- Audit-oriented reporting for security assessments
- Support for airgapped/offline environments
- Structured data handling with proper validation
- Automated dependency scanning via Dependabot and CodeQL

## Safe Harbor

We support safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts you own or with explicit permission of the account holder
- Report vulnerabilities through the channels described above

We will not pursue legal action against researchers who follow this policy.

## PGP Key

**Fingerprint:** `F839 4B2C F0FE C451 1B11 E721 8F71 D62B F438 2BC0`

```text
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaLJmxhYJKwYBBAHaRw8BAQdAaS3KAoo+AgZGR6G6+m0wT2yulC5d6zV9lf2m
TugBT+O0L3N1cHBvcnRAZXZpbGJpdGxhYnMuaW8gPHN1cHBvcnRAZXZpbGJpdGxh
YnMuaW8+iNcEExYKAH8DCwkHRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5w
Z3Bqcy5vcmexd21FpCDfIrO7bf+T6hH/8drbGLWiuEueWvSTyw4T/QMVCggEFgAC
AQIZAQKbAwIeARYhBPg5Syzw/sRRGxHnIY9x1iv0OCvABQJpiUiCBQkIXQE5AAoJ
EI9x1iv0OCvAm2sA/AqFT6XEULJCimXX9Ve6e63RX7y2B+VoBVHt+PDaPBwkAP4j
39xBoLFI6KZJ/A7SOQBkret+VONwPqyW83xfn+E7Arg4BGiyZsYSCisGAQQBl1UB
BQEBB0ArjU33Uj/x1Kc7ldjVIM9UUCWMTwDWgw8lB/mNESb+GgMBCAeIvgQYFgoA
cAWCaLJmxgkQj3HWK/Q4K8BFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBn
cGpzLm9yZ4msIB6mugSL+LkdT93+rSeNePtBY4Aj+O6TRFU9aKiQApsMFiEE+DlL
LPD+xFEbEechj3HWK/Q4K8AAALEXAQDqlsBwMP2XXzXDSnNNLg8yh1/zQcxT1zZ1
Z26lyM7L6QD+Lya5aFe74WE3wTys5ykGuWkHYEgba+AyZNmuPhwMGAc=
=9zSi
-----END PGP PUBLIC KEY BLOCK-----
```

## Contact

For general security questions, open a GitHub Issue. For vulnerability reports, use [Private Vulnerability Reporting](https://github.com/EvilBit-Labs/opnDossier/security/advisories/new) or email [support@evilbitlabs.io](mailto:support@evilbitlabs.io).

---

Thank you for helping keep opnDossier and its users secure!
