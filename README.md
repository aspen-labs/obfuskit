# 🛡️ ObfusKit

**Enterprise-Ready WAF Efficacy Testing Platform**

ObfusKit is a powerful, high-performance CLI toolkit designed to test Web Application Firewall (WAF) efficacy and application resilience against advanced evasion techniques. With support for parallel processing, batch operations, and comprehensive automation features, ObfusKit delivers enterprise-grade security testing capabilities.

## ✨ Key Features

- 🚀 **High-Performance Parallel Processing** - Multi-threaded testing with up to 10x speed improvements
- 📊 **Enterprise Automation** - JSON output, CI/CD integration, and progress tracking
- 🎯 **11 Attack Types** - XSS, SQLi, Command Injection, Path Traversal, LDAP, SSRF, XXE, and more
- 🔄 **Advanced Evasion Techniques** - 15+ encoding methods including Unicode, Base64, Best-Fit, and custom obfuscation
- 📁 **Batch Processing** - Handle multiple URLs and payloads efficiently
- 🎨 **User-Friendly CLI** - Auto-completion, progress bars, and intuitive interface
- 🔧 **Flexible Configuration** - CLI flags, YAML/JSON configs, and interactive mode

## 🚀 Quick Start

```bash
# Build the tool
go build -o obfuskit .

# Basic usage - Generate XSS evasions
./obfuskit -attack xss -payload '<script>alert(1)</script>'

# High-performance batch testing
./obfuskit -attack xss,sqli -url-file targets.txt -threads 8 -progress

# Enterprise automation
./obfuskit -attack all -payload-file payloads.txt -format json

# Install auto-completion
./scripts/install-completion.sh
```

## 📈 Performance Comparison

| Feature | Traditional Tools | ObfusKit |
|---------|------------------|----------|
| **Parallel Processing** | ❌ Sequential | ✅ Multi-threaded (10x faster) |
| **Batch URLs** | ❌ One at a time | ✅ File-based batch processing |
| **Progress Tracking** | ❌ No feedback | ✅ Real-time progress bars |
| **Automation Ready** | ❌ Text output only | ✅ JSON, CSV, multiple formats |
| **Multiple Attack Types** | ❌ Single type | ✅ Combined attack testing |

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

# 🚀  Multiple attack types simultaneously
./obfuskit -attack xss,sqli,unixcmdi -payload '<script>alert(1)</script>'

# 🚀  Batch URL testing with parallel processing
./obfuskit -attack xss -payload '<script>alert(1)</script>' -url-file targets.txt -threads 5

# 🚀  Progress tracking for long operations
./obfuskit -attack all -payload-file large_payloads.txt -progress

# 🚀  JSON output for automation
./obfuskit -attack sqli -payload "' OR 1=1 --" -url https://example.com -format json

# 🚀  High-performance enterprise testing
./obfuskit -attack xss,sqli -payload-file payloads.txt -url-file targets.txt -threads 10 -progress

# 🎯  Advanced filtering for precision testing
./obfuskit -attack xss -payload '<script>alert(1)</script>' -limit 100 -complexity medium -exclude-encodings 'base64,hex'

# ⚡  Performance-optimized testing
./obfuskit -attack sqli -url https://target.com -only-successful -max-response-time 2s

# 🛡️  WAF fingerprinting and adaptive evasion
./obfuskit -attack xss -url https://target.com -fingerprint -waf-report

```

#### Available CLI Flags:
- `-attack <type(s)>` - Attack type(s): single (xss) or multiple (xss,sqli,unixcmdi)
- `-payload <string>` - Single payload to generate evasions for
- `-payload-file <file>` - File containing payloads (one per line)
- `-url <url>` - Target URL to test payloads against
- `-url-file <file>` - File containing URLs to test (one per line)
- `-output <file>` - Output file path (default: print to console)
- `-level <level>` - Evasion level: basic, medium, advanced (default: medium)
- `-encoding <method>` - Specific encoding: url, html, unicode, base64, hex, etc.
- `-report <format>` - Report format: pretty, html, pdf, csv, nuclei, json (default: pretty)
- `-threads <num>` - Number of concurrent threads (default: 1)
- `-format <fmt>` - Output format: text, json, csv (default: text)
- `-progress` - Show progress bar for long operations

**Advanced Filtering Options:**
- `-limit <num>` - Limit number of payloads to generate (0 = no limit)
- `-min-success-rate <rate>` - Minimum success rate filter (0.0-1.0)
- `-complexity <level>` - Filter by complexity: simple, medium, complex
- `-max-response-time <dur>` - Filter out slow payloads (e.g., 5s, 500ms)
- `-filter-status <codes>` - Filter by status codes (e.g., '200,404')
- `-exclude-encodings <list>` - Exclude encodings (e.g., 'base64,hex')
- `-only-successful` - Only show payloads that bypassed WAF

**WAF Intelligence Options:**
- `-fingerprint` - Enable WAF fingerprinting and adaptive evasion
- `-waf-report` - Show detailed WAF analysis report

**🤖 AI-Powered Generation Options:**
- `-ai` - Enable AI-powered payload generation
- `-ai-provider <provider>` - AI provider (`openai`, `anthropic`, `local`, `huggingface`)
- `-ai-model <model>` - Specific AI model to use
- `-ai-config <file>` - Path to AI configuration file (JSON)
- `-ai-count <number>` - Number of AI-generated base payloads to create (default: 10)
- `-ai-creativity <0.0-1.0>` - Creativity/temperature (default: 0.7)
- `-ai-context <text>` - Additional context for generation (e.g., target details)

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

## Performance & Advanced Features

### 🚀 **Batch Processing & Parallel Execution**

Process multiple URLs and payloads efficiently:

```bash
# Test multiple URLs with parallel processing
./obfuskit -attack xss -payload '<script>alert(1)</script>' -url-file targets.txt -threads 5

# Multiple attack types simultaneously
./obfuskit -attack xss,sqli,unixcmdi -payload-file payloads.txt -threads 8

# High-performance batch testing
./obfuskit -attack all -payload-file large_payloads.txt -url-file targets.txt -threads 10 -progress
```

### 📊 **Progress Tracking & Automation**

Enhanced user experience with progress indicators and JSON output:

```bash
# Progress bars for long operations
./obfuskit -attack xss -url-file targets.txt -progress

# JSON output for CI/CD pipelines
./obfuskit -attack sqli -payload "' OR 1=1 --" -url https://example.com -format json

# Automation-friendly output
./obfuskit -attack xss,sqli -payload-file payloads.txt -url-file targets.txt -format json -progress
```

### 🎯 **Advanced Filtering & Precision Testing**

Fine-tune your testing with sophisticated filtering options:

```bash
# Limit payload count for quick testing
./obfuskit -attack xss -payload '<script>alert(1)</script>' -limit 50

# Filter by payload complexity
./obfuskit -attack sqli -payload "' OR 1=1 --" -complexity simple

# Exclude specific encoding methods
./obfuskit -attack xss -payload-file payloads.txt -exclude-encodings 'base64,hex,unicode'

# Only successful bypasses (URL testing)
./obfuskit -attack xss -url https://target.com -only-successful -max-response-time 2s

# Filter by HTTP status codes
./obfuskit -attack sqli -url https://target.com -filter-status '200,404'

# Minimum success rate filter
./obfuskit -attack all -url-file targets.txt -min-success-rate 0.3
```

### 🛡️ **WAF Intelligence & Adaptive Evasion**

Automatically detect and adapt to Web Application Firewalls:

```bash
# Auto-detect WAF and adapt evasion strategy
./obfuskit -attack xss -url https://target.com -fingerprint

# Get detailed WAF analysis report
./obfuskit -attack sqli -url https://target.com -fingerprint -waf-report

# Combine with other features for maximum effectiveness
./obfuskit -attack xss,sqli -url https://target.com -fingerprint -threads 5 -progress

# Batch WAF analysis across multiple targets
./obfuskit -attack xss -url-file targets.txt -fingerprint -waf-report
```

### 🤖 **AI-Powered Payload Generation (GenAI)**

Generate intelligent, context-aware base payloads using LLMs and blend them with ObfusKit's evasions:

```bash
# Quick AI generation with defaults (uses env/provider defaults)
./obfuskit -attack xss -ai -ai-count 20 -ai-creativity 0.9

# Specify provider and model explicitly
./obfuskit -attack sqli -ai -ai-provider openai -ai-model gpt-4-turbo-preview -ai-count 15

# Use Anthropic
./obfuskit -attack xss -ai -ai-provider anthropic -ai-model claude-3-sonnet-20240229

# Use local LLM (Ollama/LM Studio)
./obfuskit -attack xss -ai -ai-provider local -ai-config examples/configs/ai-local.json

# Provide additional context (e.g., URL or WAF hints)
./obfuskit -attack xss -ai -ai-context "Target running CSP, reflected XSS likely in query"

# AI with baseline request/response context for enhanced evasion
./obfuskit -attack xss -payload "<script>alert('test')</script>" \
  -ai -ai-provider openai -ai-model gpt-4 \
  -ai-context "REQUEST_BASELINE: POST /api/search HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nquery=user_input&filter=active\n\nRESPONSE_BASELINE: HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"results\": [{\"id\": 1, \"name\": \"test\"}]}"

# Load AI configuration from file (overrides defaults)
./obfuskit -attack xss -ai -ai-config examples/configs/ai-openai.json
```

Environment variables (keys and defaults):

```bash
# Generic (provider-agnostic)
export OBFUSKIT_AI_PROVIDER=openai           # openai | anthropic | local | huggingface
export OBFUSKIT_AI_API_KEY=sk-...            # used when provider requires a key
export OBFUSKIT_AI_MODEL=gpt-4-turbo-preview
export OBFUSKIT_AI_ENDPOINT=http://localhost:11434/api/generate  # for local

# Provider-specific keys (also supported)
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export HUGGINGFACE_API_KEY=hf_...

# Example
export OBFUSKIT_AI_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
./obfuskit -attack sqli -ai -ai-count 10
```

Notes:
- CLI flags override env vars; env vars override built-in defaults.
- Local provider does not require an API key; set `OBFUSKIT_AI_ENDPOINT` if not default.
- See example configs: `examples/configs/ai-openai.json`, `examples/configs/ai-local.json`.

**Burp Plugin Integration:**
The Burp Suite plugin automatically captures baseline request/response context and sends it to the AI engine for enhanced payload generation. This provides context-aware evasion that understands the target application's behavior.

**Supported WAF Detection:**
- CloudFlare, AWS WAF, Azure WAF
- Akamai, ModSecurity, Imperva
- F5 BIG-IP, Barracuda, Fortinet
- Sucuri, Wallarm, Radware
- And more...
```

### 🚀 **Auto-completion Support**

Install shell auto-completion for better CLI experience:

```bash
# Install auto-completion (bash/zsh)
./scripts/install-completion.sh

# Test completion
obfuskit -<TAB>
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

## 🎯 Enterprise Use Cases

### DevSecOps & CI/CD Integration
```bash
# Automated security testing in CI/CD pipelines
./obfuskit -attack all -payload-file security_payloads.txt -url $TARGET_URL -format json > results.json

# Regression testing with multiple attack vectors
./obfuskit -attack xss,sqli,unixcmdi -url-file staging_urls.txt -threads 8 -progress -format json
```

### Security Team Workflows
```bash
# Comprehensive WAF assessment
./obfuskit -attack all -payload-file comprehensive_payloads.txt -url-file production_endpoints.txt -threads 10 -progress -report all

# Custom evasion testing
./obfuskit -attack xss -payload '<script>alert(1)</script>' -encoding unicode,base64,bestfit -url https://target.com
```

### Performance Testing
```bash
# High-throughput testing (handles 1000+ payloads efficiently)
./obfuskit -attack all -payload-file large_dataset.txt -url-file targets.txt -threads 15 -progress

# Quick validation testing
./obfuskit -attack xss,sqli -payload-file quick_test.txt -url-file endpoints.txt -threads 5 -format json
```

## 📊 Benchmarks

- **10x Speed Improvement**: Parallel processing vs sequential testing
- **Memory Efficient**: Handles 10,000+ payloads with minimal memory usage
- **Scalable**: Successfully tested with 50+ concurrent threads
- **Enterprise Ready**: JSON output integrates seamlessly with security orchestration platforms

## 📦 Installation & Setup

### Basic Installation
```bash
# Clone and build
git clone <repository-url>
cd obfuskit
go build -o obfuskit .
```

### Enhanced Setup (Recommended)
```bash
# Build with auto-completion support
go build -o obfuskit .

# Install shell auto-completion (bash/zsh)
./scripts/install-completion.sh

# Verify installation
./obfuskit -help
obfuskit -<TAB>  # Test auto-completion
```

### Docker Support (Coming Soon)
```bash
# Run with Docker
docker run obfuskit:latest -attack xss -payload '<script>alert(1)</script>'
```

## Requirements

- Go 1.19 or later
- No external dependencies required for basic functionality
- Optional: bash-completion package for enhanced CLI experience

## 🗺️ Roadmap

### ✅ Recently Completed (v2.0)
- **✅ Parallel Processing** - Multi-threaded testing with configurable worker count
- **✅ Batch URL Processing** - File-based URL testing for large-scale assessments
- **✅ JSON Output Format** - Machine-readable output for automation and CI/CD
- **✅ Progress Indicators** - Real-time progress bars with ETA calculations
- **✅ Auto-completion Scripts** - Enhanced CLI experience for bash/zsh
- **✅ Multiple Attack Types** - Combined attack testing (e.g., `-attack xss,sqli,unixcmdi`)
- **✅ Advanced Filtering** - Filter by complexity, limit payloads, exclude encodings, response criteria

### ✅ Recently Completed (v2.1)
- **✅ WAF Fingerprinting** - Automatic WAF detection with adaptive evasion strategies

### 🎯 Planned Features (v3.0)
- **📈 Rate Limiting** - Intelligent request throttling and retry mechanisms
- **🔍 Response Analysis** - Advanced pattern recognition for bypass detection
- **🐳 Container Support** - Docker images and Kubernetes deployment
- **📱 Web Dashboard** - Real-time monitoring and result visualization
- **🤖 AI-Powered Evasions** - Machine learning-based payload generation

## Contributing

We welcome contributions! Here's how to get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Priority Areas
- 🧪 **Testing**: Additional test coverage for parallel processing
- 📚 **Documentation**: API documentation and usage guides
- 🎨 **UI/UX**: Web dashboard development
- 🔧 **Performance**: Optimization for large-scale deployments

## License

This project is licensed under the MIT License - see the LICENSE file for details.