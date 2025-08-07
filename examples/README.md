# ObfusKit Examples

This directory contains comprehensive examples, configurations, and scripts to help you get started with ObfusKit quickly and effectively.

## 📁 Directory Structure

```
examples/
├── configs/           # Example configuration files
├── payloads/         # Example payload files
├── scripts/          # Automated testing scripts
├── urls/             # Example target URL lists
└── README.md         # This file
```

## 🔧 Configuration Examples

### Basic XSS Testing
**File:** `configs/basic-xss-testing.yaml`

Simple XSS payload generation for beginners:
```bash
./obfuskit -config examples/configs/basic-xss-testing.yaml
```

### Advanced SQL Injection Testing
**File:** `configs/sqli-advanced-testing.yaml`

Advanced SQLi testing with custom payloads:
```bash
./obfuskit -config examples/configs/sqli-advanced-testing.yaml
```

### Comprehensive WAF Testing
**File:** `configs/comprehensive-waf-testing.yaml`

Multi-attack type testing with file input:
```bash
./obfuskit -config examples/configs/comprehensive-waf-testing.yaml
```

### Command Injection Testing
**File:** `configs/command-injection-testing.yaml`

Unix/Windows command injection testing:
```bash
./obfuskit -config examples/configs/command-injection-testing.yaml
```

### Enterprise Batch Testing
**File:** `configs/enterprise-batch-testing.yaml`

Enterprise-scale testing configuration:
```bash
./obfuskit -config examples/configs/enterprise-batch-testing.yaml \
    -url-file examples/urls/targets.txt \
    -threads 10 \
    -progress
```

## 📜 Automated Scripts

### Quick XSS Test Script
**File:** `scripts/quick-xss-test.sh`

Quickly test a single URL for XSS vulnerabilities:

```bash
# Basic usage
./examples/scripts/quick-xss-test.sh https://example.com/search?q=

# Example output:
🛡️  ObfusKit Quick XSS Test
==================================
🎯 Target: https://example.com/search?q=

🚀 Running quick XSS tests...

Test 1: <script>alert(1)</script>
✅ Payload blocked

Test 2: <img src=x onerror=alert(1)>
⚠️  Potential XSS vulnerability detected!
```

### Enterprise Batch Test Script
**File:** `scripts/enterprise-batch-test.sh`

Comprehensive enterprise-grade testing across multiple targets:

```bash
# Default usage (uses example files)
./examples/scripts/enterprise-batch-test.sh

# Custom configuration
./examples/scripts/enterprise-batch-test.sh \
    examples/urls/targets.txt \
    examples/payloads/enterprise_payloads.txt \
    20

# Example output:
🛡️  ObfusKit Enterprise Batch Testing
==========================================
📋 Configuration:
  URL File: examples/urls/targets.txt
  Payload File: examples/payloads/enterprise_payloads.txt
  Threads: 20
  Output Directory: batch_test_results_20241120_143022

🚀 Starting enterprise batch testing...

🎯 Testing xss attacks...
✅ xss testing completed

🎯 Testing sqli attacks...
✅ sqli testing completed
```

## 🎯 Payload Files

### Comprehensive Attacks
**File:** `payloads/comprehensive_attacks.txt`

Contains basic to intermediate payloads for all attack types:
- XSS (Cross-Site Scripting)
- SQL Injection
- Command Injection
- Path Traversal
- LDAP Injection
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)

### Enterprise Payloads
**File:** `payloads/enterprise_payloads.txt`

Advanced, enterprise-grade payloads for sophisticated testing:
- Complex encoding bypasses
- Advanced evasion techniques
- Real-world attack scenarios
- High-impact vulnerability proofs

## 🌐 Target URL Lists

### Development Targets
**File:** `urls/targets.txt`

Example target URLs for testing:
- Development environments
- API endpoints
- Local testing instances
- Security lab applications

⚠️ **Security Note:** Replace example URLs with your authorized test targets.

## 🚀 Quick Start Examples

### 1. Basic Single-Target Test
```bash
# Test XSS against a single URL
./obfuskit -attack xss -url https://example.com/search -progress
```

### 2. Multi-Attack Testing
```bash
# Test multiple attack types
./obfuskit -attack xss,sqli,unixcmdi \
    -url https://example.com/api \
    -threads 5 \
    -progress \
    -fingerprint
```

### 3. Batch URL Testing
```bash
# Test multiple URLs from file
./obfuskit -attack xss \
    -url-file examples/urls/targets.txt \
    -threads 10 \
    -progress \
    -format json \
    -output results.json
```

### 4. Custom Payload Testing
```bash
# Use custom payloads
./obfuskit -attack xss \
    -payload-file examples/payloads/comprehensive_attacks.txt \
    -url https://example.com/form \
    -complexity medium \
    -only-successful
```

### 5. Advanced Enterprise Testing
```bash
# Full enterprise testing with WAF fingerprinting
./obfuskit -attack xss,sqli,unixcmdi \
    -payload-file examples/payloads/enterprise_payloads.txt \
    -url-file examples/urls/targets.txt \
    -threads 20 \
    -progress \
    -fingerprint \
    -waf-report \
    -format json \
    -output enterprise_results.json \
    -report html \
    -min-success-rate 0.1 \
    -exclude-encodings 'base64'
```

## 📊 Output Examples

### Console Output
```
🛡️  OBFUSKIT v2.1.0
Enterprise WAF Testing Platform

🚀 Starting ObfusKit with command line arguments...

==============================
CONFIGURATION VALIDATION
==============================
⚠️  Configuration Warnings:
1. target.url: Using HTTP instead of HTTPS
✅ Configuration is valid but has warnings above.

==============================
CONFIGURATION SUMMARY
==============================
Action: Send to URL
Attack: xss
Payload: Enter Manually
Evasion Level: Medium
Target: URL
Report: Pretty Terminal
URL: https://example.com/test

🔧 Generating payloads...
🔀 Processing multiple attack types: [xss sqli]
Generating payloads [████████████] 100.0% (50/50) ETA: 0s
✅ Generating payloads completed!

🌐 Testing payloads against URL...
Testing requests [████████████] 100.0% (150/150) ETA: 0s
✅ URL testing completed!

🧠 WAF Fingerprinting Results:
Detected WAF: Cloudflare
Confidence: 95%
Recommended evasions: unicode, html, mixed-case
```

### JSON Output
```json
{
  "metadata": {
    "timestamp": "2024-01-20T10:30:45Z",
    "tool": "ObfusKit",
    "version": "2.1.0"
  },
  "config": {
    "action": "send_to_url",
    "attack_type": "xss",
    "evasion_level": "medium",
    "target_url": "https://example.com/test"
  },
  "summary": {
    "total_payloads": 50,
    "total_variants": 150,
    "successful_tests": 12,
    "failed_tests": 138,
    "success_rate": 0.08
  },
  "request_results": [
    {
      "payload": "<img src=x onerror=alert(1)>",
      "url": "https://example.com/test",
      "method": "GET",
      "status_code": 200,
      "blocked": false,
      "response_time_ms": 245,
      "technique": "HTMLVariants",
      "part": "query"
    }
  ]
}
```

## 🔒 Security Best Practices

### 1. Authorization
- Only test applications you own or have explicit permission to test
- Obtain proper authorization before conducting security testing
- Follow responsible disclosure practices

### 2. Environment Safety
- Use isolated testing environments when possible
- Avoid testing production systems
- Be mindful of rate limiting and service availability

### 3. Data Protection
- Be careful with sensitive payloads that could expose data
- Sanitize logs and reports before sharing
- Use secure channels for transmitting test results

## 🆘 Troubleshooting

### Common Issues

**1. Permission Denied**
```bash
chmod +x examples/scripts/*.sh
```

**2. File Not Found**
```bash
# Ensure you're in the ObfusKit root directory
cd /path/to/obfuskit
./examples/scripts/quick-xss-test.sh
```

**3. URL Connection Errors**
- Check target accessibility
- Verify network connectivity
- Consider firewall/proxy settings

**4. High Memory Usage**
```bash
# Reduce thread count for large batch tests
./obfuskit -threads 5 -limit 100
```

## 📞 Support

For additional help and examples:
- Check the main README.md
- Review the help output: `./obfuskit -help`
- Use version information: `./obfuskit -version-full`

## 🚀 Next Steps

1. **Start Simple:** Begin with the basic XSS configuration
2. **Learn Gradually:** Progress to multi-attack testing
3. **Scale Up:** Use enterprise batch testing for comprehensive assessment
4. **Customize:** Create your own configurations and payload files
5. **Automate:** Integrate ObfusKit into your CI/CD security pipelines
