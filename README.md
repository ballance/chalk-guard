# Chalk Guard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Security Tool](https://img.shields.io/badge/purpose-security-red.svg)](https://github.com/ballance/chalk-guard)
[![NPM Supply Chain](https://img.shields.io/badge/detects-npm%20supply%20chain%20attacks-orange.svg)](https://github.com/ballance/chalk-guard)

A Python-based security tool for detecting the September 2025 npm supply chain compromise that affected popular packages including chalk, debug, and related dependencies.

## Why I Built This

On September 8th, 2025, the npm ecosystem experienced one of its most significant supply chain attacks to date. Popular packages like chalk, debug, and dozens of others were compromised, affecting potentially millions of applications worldwide. As I watched the chaos unfold, I was reminded of the famous [xkcd comic #2347](https://xkcd.com/2347/) about modern digital infrastructure:

> *"Someday, someone will look at the foundations of modern digital infrastructure and see that it's all maintained by a project some random person in Nebraska has been thanklessly maintaining since 2003."*

This comic perfectly captures the fragility of our dependency chains. We build complex applications on top of countless packages, often maintained by solo developers or small teams working in their spare time. When one of these packages gets compromised, the ripple effects can be catastrophic.

I realized that while large organizations might have sophisticated security scanning tools, individual developers and smaller teams were left vulnerable. They needed a way to quickly check if their applications were affected by this attack. That's when I decided to build Chalk Guard.

Within hours of the attack, I had a working prototype. As I shared it with colleagues and the broader community, the response was overwhelming. Developers were desperate for a tool that could help them identify compromised packages in their production applications. What started as a personal project to protect my own applications quickly evolved into something that could help the entire community.

This tool represents more than just code – it's a reminder that our open source ecosystem is only as strong as we make it together. By sharing tools like this, we can help protect each other from supply chain attacks and make the entire ecosystem more resilient.

## Overview

This tool scans web applications to identify if they're using compromised npm packages from the September 8th, 2025 supply chain attack. It performs deep analysis of JavaScript files, CDN resources, and package dependencies to detect malicious code signatures and compromised package versions.

### Key Features

- **Multi-page scanning**: Analyzes main URL and follows first-layer links
- **Package detection**: Identifies 60+ compromised npm packages
- **Malware signature matching**: Detects obfuscated code and known malicious patterns
- **CDN analysis**: Checks for suspicious CDN usage and malicious domains
- **Comprehensive reporting**: Generates detailed vulnerability reports with confidence levels
- **Batch processing**: Scan multiple URLs from a file

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Internet connection for scanning websites

### Setup

1. Clone the repository:
```bash
git clone https://github.com/ballance/chalk-guard.git
cd chalk-guard
```

2. Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan

Scan a single website:
```bash
python supply.py https://example.com
```

### Command Line Options

```bash
python supply.py [URL] [OPTIONS]

Options:
  -v, --verbose         Enable verbose output for detailed logging
  -o, --output FILE     Save JSON results to specified file
  --batch FILE          Scan multiple URLs from a file (one per line)
  --no-follow          Don't follow first-layer links (faster scan)
  --deep               Perform deep recursive scanning (slower but thorough)
```

### Examples

1. **Scan with verbose output:**
```bash
python supply.py https://example.com -v
```

2. **Batch scan multiple sites:**
```bash
echo "https://site1.com" > urls.txt
echo "https://site2.com" >> urls.txt
python supply.py --batch urls.txt -o results.json
```

3. **Quick scan without following links:**
```bash
python supply.py https://example.com --no-follow
```

4. **Deep scan with JSON output:**
```bash
python supply.py https://example.com --deep -o scan_results.json
```

## Output Files

The scanner automatically creates two tracking files:

- **sus.txt**: Contains URLs identified as vulnerable with details about compromised packages and confidence levels
- **safe.txt**: Contains URLs that appear to be safe after scanning

## Understanding the Results

### Confidence Levels

- **HIGH**: Malware signatures detected, strong indicators of compromise
- **MEDIUM**: Compromised packages found, suspicious patterns detected
- **LOW**: Minor suspicious indicators, further investigation recommended
- **NONE**: No indicators of compromise detected

### Key Detection Categories

1. **Compromised Packages**: Direct usage of affected npm packages
2. **Malware Signatures**: Code patterns matching known malicious implementations
3. **Suspicious CDNs**: Usage of compromised CDN resources
4. **Obfuscation**: Heavily obfuscated code that may hide malicious functionality
5. **Known Malware**: Files matching known malicious file hashes

## Compromised Packages

The tool detects the following compromised packages (September 2025 attack):

### Core Packages
- chalk (5.6.1)
- debug (4.4.2)
- ansi-regex (6.2.1)
- ansi-styles (6.2.2)
- supports-color (10.2.1)
- strip-ansi (7.1.1)

### Additional Affected Packages
- color-convert, color-name, color-string
- wrap-ansi, slice-ansi
- has-ansi, supports-hyperlinks
- error-ex, is-arrayish, simple-swizzle
- duckdb and related packages
- prebid and related packages

## Security Recommendations

If the tool detects compromised packages:

1. **Immediate Actions:**
   - Clear all npm/yarn caches
   - Delete node_modules and package-lock.json
   - Update all dependencies to latest secure versions
   - Run `npm audit fix --force`

2. **Rebuild and Deploy:**
   - Rebuild application from clean sources
   - Redeploy to production environments
   - Monitor for suspicious network activity

3. **Security Measures:**
   - Rotate all API keys and credentials
   - Review cryptocurrency transaction logs
   - Implement dependency scanning in CI/CD

## How It Works

The detector uses multiple detection techniques:

1. **Static Analysis**: Scans JavaScript files for malicious code patterns
2. **Package Detection**: Identifies usage of compromised package versions
3. **CDN Analysis**: Checks for loading resources from malicious CDNs
4. **Obfuscation Detection**: Identifies heavily obfuscated code blocks
5. **Signature Matching**: Compares against database of known malware signatures

## Testing

Run the test suite to verify functionality:
```bash
python -m pytest test_security.py -v
python -m pytest test_demo.py -v
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Areas for Contribution

- Additional malware signatures
- New detection techniques
- Performance optimizations
- Documentation improvements
- Test coverage
- Support for additional package managers (yarn, pnpm)
- Integration with CI/CD pipelines

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is provided for security research and defensive purposes only. It should be used to identify and remediate security vulnerabilities in your own applications or with proper authorization.

## Support

If you find this tool helpful, please consider:
- Starring the repository
- Sharing with your security team
- Contributing improvements
- Reporting false positives/negatives

## Acknowledgments

- Thanks to the security research community for quickly identifying and documenting the compromised packages
- Inspired by the need to protect the developer community from supply chain attacks
- Built with urgency to help developers quickly identify and remediate compromised dependencies

## Contact

For security concerns or private vulnerability reports, please open an issue on GitHub.

---

**Remember**: As [xkcd #2347](https://xkcd.com/2347/) reminds us, modern digital infrastructure depends on countless maintainers. Stay vigilant, keep your dependencies updated, and help each other stay secure.

**Note**: This tool was developed in response to the September 2025 npm supply chain attack. Keep the tool updated as new indicators of compromise are discovered.
