# ObfusKit

ObfusKit is a flexible CLI toolkit designed to test WAF efficacy and application resilience against evasion techniques and obfuscated payloads. Whether you're testing URL paths, command strings, or encoding mechanisms, ObfusKit provides varying levels of obfuscation to simulate real-world attack variants.

## Features
Three Levels of Obfuscation/Evasion:

🔹 Basic: Minimal transformations (e.g., simple encoding or path tweaks).

🔸 Medium: Moderate evasions that blend techniques (e.g., mixed encodings, partial command obfuscation).

🔺 Advanced: Aggressive and stealthy evasion strategies meant to bypass well-configured WAFs.

##Three Obfuscation Categories:

### Paths: 
- Obfuscate URL paths with encodings, alternate separators, and tricky combinations.

### Commands: 
Obfuscate shell/CLI commands using spacing tricks, comments, encodings, etc.

### Encodings: 
Apply multiple encoding schemes including best-fit/worst-fit representations.

#### Encoding Techniques Supported:
- Hexadecimal
- Base64
- Unicode Escapes
- URL Encoding
- Best-Fit and Worst-Fit Encodings (tailored for WAF bypass testing)

### Use Cases
- Test how your WAF handles advanced evasion techniques
- Analyze your application’s input sanitization robustness
- Build regression suites for security tooling with evolving evasions
- Evaluate encoding and obfuscation-based payload handling

### Usage and Installation - TODO 