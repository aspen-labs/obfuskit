# ObfusKit

ObfusKit is a flexible CLI toolkit designed to test WAF efficacy and application resilience against evasion techniques and obfuscated payloads. Whether you're testing URL paths, command strings, or encoding mechanisms, ObfusKit provides varying levels of obfuscation to simulate real-world attack variants.

## Quick Start

```bash
# Build the tool
go build -o obfuskit .

# Show help
./obfuskit -help

# Quick payload generation
./obfuskit -attack xss -payload '<script>alert(1)</script>'

# Test against a URL
./obfuskit -attack xss -payload '<script>alert(1)</script>' -url https://example.com
```

## Features
Three Levels of Obfuscation/Evasion:

🔹 Basic: Minimal transformations (e.g., simple encoding or path tweaks).

🔸 Medium: Moderate evasions that blend techniques (e.g., mixed encodings, partial command obfuscation).

🔺 Advanced: Aggressive and stealthy evasion strategies meant to bypass well-configured WAFs.

## Three Obfuscation Categories:

### Paths: 
- Obfuscate URL paths with encodings, alternate separators, and tricky combinations.

### Commands: 
Obfuscate shell/CLI commands using spacing tricks, comments, encodings, etc.

### Encodings: 
Apply multiple encoding schemes including best-fit/worst-fit representations.

#### Attack Types Supported:
- **XSS** (`xss`) - Cross-Site Scripting payloads
- **SQLi** (`sqli`) - SQL Injection payloads  
- **Unix Command Injection** (`unixcmdi`) - Unix/Linux command injection
- **Windows Command Injection** (`wincmdi`) - Windows command injection
- **Path Traversal** (`path`) - Directory traversal attacks
- **File Access** (`fileaccess`) - File inclusion/access attacks
- **LDAP Injection** (`ldapi`) - LDAP injection payloads
- **SSRF** (`ssrf`) - Server-Side Request Forgery
- **XXE** (`xxe`) - XML External Entity attacks
- **Generic** (`generic`) - General purpose evasions
- **All** (`all`) - Apply all applicable attack types

#### Encoding Techniques Supported:
- **URL Encoding** - Standard and double URL encoding
- **HTML Entities** - HTML entity encoding
- **Unicode Escapes** - Various Unicode representations
- **Base64** - Base64 encoding variants
- **Hexadecimal** - Hex encoding
- **Mixed Case** - Case variation techniques
- **UTF-8** - UTF-8 byte sequences
- **Best-Fit Encodings** - Tailored for WAF bypass testing
- **Command Obfuscation** - Unix/Windows command hiding techniques
- **Path Traversal** - Directory traversal encoding variants

### Use Cases
- Test how your WAF handles advanced evasion techniques
- Analyze your application’s input sanitization robustness
- Build regression suites for security tooling with evolving evasions
- Evaluate encoding and obfuscation-based payload handling

## Usage

ObfusKit offers three ways to use the tool:

### 1. Simple CLI Flags (Recommended for Quick Testing)

```bash
# Basic payload generation
./obfuskit -attack xss -payload '<script>alert(1)</script>'

# Advanced evasion level
./obfuskit -attack sqli -payload "' OR 1=1 --" -level advanced

# Test against a URL
./obfuskit -attack xss -payload '<script>alert(1)</script>' -url https://example.com

# Use payload file and save output
./obfuskit -attack xss -payload-file payloads.txt -output results.txt

# Specific encoding
./obfuskit -attack xss -payload '<script>alert(1)</script>' -encoding unicode

# Multiple options combined
./obfuskit -attack sqli -payload "' UNION SELECT * FROM users --" -level advanced -encoding base64 -output sqli_test.txt
```

#### Available CLI Flags:
- `-attack <type>` - Attack type (xss, sqli, unixcmdi, wincmdi, path, fileaccess, ldapi)
- `-payload <string>` - Single payload to generate evasions for
- `-payload-file <file>` - File containing payloads (one per line)
- `-url <url>` - Target URL to test payloads against
- `-output <file>` - Output file path (default: print to console)
- `-level <level>` - Evasion level: basic, medium, advanced (default: medium)
- `-encoding <method>` - Specific encoding: url, html, unicode, base64, hex, etc.
- `-report <format>` - Report format: pretty, html, pdf, csv, nuclei, json (default: pretty)

### 2. Configuration Files

Generate an example configuration file:
```bash
./obfuskit -generate-config yaml
```

Run with a configuration file:
```bash
./obfuskit -config config.yaml
```

### 3. Interactive Mode

For a guided experience with menu-driven interface:
```bash
./obfuskit
```

### Server Mode

Start the integration webservice for Burp Suite integration:
```bash
./obfuskit -server -config config_server.yaml
```

## Example Output

When you run a simple command like:
```bash
./obfuskit -attack xss -payload '<script>alert(1)</script>'
```

You'll get output like:
```
Using command line arguments...

==============================
CONFIGURATION SUMMARY
==============================
Action: Generate Payloads
Attack: xss
Payload: Enter Manually
Evasion Level: Medium
Target: File
Report: Pretty Terminal
URL: 
==============================

🔧 Generating payloads...
✅ Generated 6266 payload variants across 120 base payloads
✅ Payloads saved to:
  - payloads_output.txt (detailed with metadata)
  - payloads_simple.txt (one payload per line)

============================================================
TEST SUMMARY
============================================================
Total Base Payloads: 120
Total Variants Generated: 6266
Attack Types: xss
Evasion Types: Base64Variants, BestFitVariants, HTMLVariants, UnicodeVariants, HexVariants, OctalVariants
============================================================

✅ WAF testing completed successfully!
```

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd obfuskit

# Build the tool
go build -o obfuskit .

# Run
./obfuskit -help
```

## Advanced Usage

### Testing Against Live URLs

When testing against a URL, ObfusKit will automatically test various injection points:
- HTTP headers
- Query parameters  
- POST body (form data and JSON)
- Different HTTP methods

```bash
./obfuskit -attack xss -payload '<script>alert(1)</script>' -url https://target.com/test
```

### Custom Payload Files

Create a file with one payload per line:
```bash
echo '<script>alert(1)</script>' > my_payloads.txt
echo '<img src=x onerror=alert(1)>' >> my_payloads.txt
./obfuskit -attack xss -payload-file my_payloads.txt -level advanced
```

### Report Generation

Generate different report formats:
```bash
# HTML report
./obfuskit -attack xss -payload '<script>alert(1)</script>' -url https://target.com -report html

# Nuclei templates
./obfuskit -attack sqli -payload "' OR 1=1 --" -report nuclei

# All formats
./obfuskit -attack xss -payload '<script>alert(1)</script>' -url https://target.com -report all
```

## Requirements

- Go 1.19 or later
- No external dependencies required for basic functionality

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.