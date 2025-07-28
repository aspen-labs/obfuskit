Command Evasion Generator
===============================

Overview:
---------
This module (`UnixCmdVariants` and `WindowsCmdVariants`) generates multiple evasion techniques for Unix/Linux and Windows shell commands. 
It obfuscates basic payloads to evade basic WAFs, SIEMs, IDS/IPS systems, and other detection mechanisms.

It supports three levels of evasion:
- Basic
- Medium
- Advanced

Each level progressively adds more sophisticated obfuscation methods.

----------------------------------
### Supported Evasion Techniques: Unix
----------------------------------

**Basic Techniques:**
- Backslash Evasion: Randomly adds backslashes between characters.
- Quote Variations: Randomly wraps words with single or double quotes.
- Spacing Techniques: Inserts random spaces or tabs between words.
- Command Chaining: Injects harmless commands using `;`, `&&`, `||`.
- Binary Path Obfuscation: Prefixes commands with `/bin/`, `/usr/bin/`, or `$(which cmd)`.
- Inline Comments: Adds inline shell comments to break simple parsers.
- Redirection Noise: Adds noise like `>/dev/null`, `2>&1`.
- Variable Assignment: Assigns command to a variable and executes it.
- Randomized Case: Randomly uppercases/lowercases characters.

**Medium Techniques:**
- Command Evaluation: Wraps payload in `eval`, `bash -c`.
- Process Substitution: Uses `$()` syntax for delayed execution.
- Here-String Techniques: Uses shell here-strings.
- IFS Modification: Changes the Internal Field Separator (IFS) to alter argument parsing.
- Backticks Substitution: Uses backtick (`) command substitution.
- String Concatenation: Breaks strings into fragments and reconstructs at runtime.
- Double Evaluation: Multiple nested evaluations.
- Wildcard Path Evasion: Uses `?` and `*` wildcards to confuse simple scanners.
- Hex Encoding: Encodes payloads in hexadecimal.

**Advanced Techniques:**
- Base64 Techniques: Encodes payload in Base64, then decodes at runtime.
- Arithmetic Expansion: Obfuscates values through shell arithmetic.
- Reverse Shell Techniques: Tricks to create reverse shells for remote access.
- File Descriptor Tricks: Manipulates file descriptors.
- Unicode Escapes: Inserts Unicode escape sequences.
- Runtime Script Generation: Builds shell scripts dynamically and executes them.
- Function Obfuscation: Defines obfuscated shell functions to hide commands.
- Advanced IFS Tricks: More complex IFS manipulation and splitting.

----------------------------------
### Supported Evasion Techniques: Windows
----------------------------------

**Basic Techniques:**
- Caret Escaping: Inserting ^ to escape characters.
- Quote Manipulation: Using mixed ' and " quotes.
- Spacing Tricks: Inserting random spaces, tabs.
- Command Chaining: Using &, &&, || operators.
- Environment Variables: Using %COMSPEC%, %SYSTEMROOT%, %windir%.
- Inline Comments: Leveraging REM statements.
- Output Redirection: Adding >nul, 2>&1 to hide output.
- Randomized Case: Random capitalization of commands.

**Medium Techniques:**
- Command Evaluation: Using cmd /c, call, or delayed variable expansion.
- String Fragmentation: Breaking up commands with set and delayed variables.
- Encoded Spaces: Using " " and concatenations.
- Special Character Injection: Using !, ^, & inside strings.
- Hex Encoding: Representing parts of commands as hex.
- Variable Rebuilding: Building the command at runtime with variables.

**Advanced Techniques:**
- Base64 Techniques: Encode command, then decode and execute.
- Unicode Encoding: Inserting Unicode escape sequences.
- Code Page Manipulation: Changing codepages with chcp.
- Scriptlet Execution: Executing commands via .vbs, .js, or mshta.
- Obfuscated Batch Scripts: Dynamically generating and executing batch files.
- ADS Abuse: Using NTFS Alternate Data Streams.

Notes:
------
- Randomness: Some techniques involve randomness. Output may vary on different runs.