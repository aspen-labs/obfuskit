#compdef obfuskit

# Zsh completion for obfuskit

_obfuskit() {
    local context state line
    typeset -A opt_args

    _arguments \
        '-help[Show help information]' \
        '-config[Path to configuration file]:config file:_files' \
        '-generate-config[Generate example config]:format:(yaml json)' \
        '-server[Start integration webservice]' \
        '-attack[Attack type(s)]:attack type:_obfuskit_attack_types' \
        '-payload[Single payload to generate evasions for]:payload:' \
        '-payload-file[File containing payloads]:payload file:_files' \
        '-url[Target URL to test payloads against]:url:_urls' \
        '-url-file[File containing URLs]:url file:_files' \
        '-output[Output file path]:output file:_files' \
        '-level[Evasion level]:level:(basic medium advanced)' \
        '-encoding[Specific encoding method]:encoding:_obfuskit_encodings' \
        '-report[Report format]:report:(pretty terminal html pdf csv nuclei json auto all)' \
        '-threads[Number of concurrent threads]:threads:(1 2 4 5 8 10)' \
        '-format[Output format]:format:(text json csv)' \
        '-progress[Show progress bar for long operations]' \
        '-limit[Limit number of payloads]:limit:(10 50 100 500 1000)' \
        '-min-success-rate[Minimum success rate]:rate:(0.1 0.2 0.5 0.8)' \
        '-complexity[Filter by complexity]:complexity:(simple medium complex)' \
        '-max-response-time[Max response time]:time:(1s 2s 5s 10s 500ms)' \
        '-filter-status[Filter by status codes]:codes:(200 404 403 500)' \
        '-exclude-encodings[Exclude encodings]:encodings:(base64 hex unicode url html)' \
        '-only-successful[Only show successful bypasses]' \
        '-fingerprint[Enable WAF fingerprinting and adaptive evasion]' \
        '-waf-report[Show detailed WAF analysis report]'
}

_obfuskit_attack_types() {
    local attacks
    attacks=(
        'xss:Cross-Site Scripting'
        'sqli:SQL Injection' 
        'sql:SQL Injection'
        'unixcmdi:Unix Command Injection'
        'unix:Unix Command Injection'
        'wincmdi:Windows Command Injection'
        'windows:Windows Command Injection'
        'oscmdi:OS Command Injection'
        'os:OS Command Injection'
        'path:Path Traversal'
        'fileaccess:File Access'
        'file:File Access'
        'ldapi:LDAP Injection'
        'ldap:LDAP Injection'
        'ssrf:Server-Side Request Forgery'
        'xxe:XML External Entity'
        'generic:Generic evasions'
        'all:All attack types'
    )
    _describe 'attack types' attacks
}

_obfuskit_encodings() {
    local encodings
    encodings=(
        'url:URL encoding'
        'doubleurl:Double URL encoding'
        'double-url:Double URL encoding'
        'html:HTML entities'
        'unicode:Unicode escapes'
        'base64:Base64 encoding'
        'b64:Base64 encoding'
        'hex:Hexadecimal encoding'
        'octal:Octal encoding'
        'bestfit:Best-fit encoding'
        'best-fit:Best-fit encoding'
        'mixedcase:Mixed case'
        'mixed-case:Mixed case'
        'utf8:UTF-8 sequences'
        'utf-8:UTF-8 sequences'
        'unixcmd:Unix command obfuscation'
        'unix-cmd:Unix command obfuscation'
        'windowscmd:Windows command obfuscation'
        'windows-cmd:Windows command obfuscation'
        'pathtraversal:Path traversal encoding'
        'path-traversal:Path traversal encoding'
    )
    _describe 'encoding methods' encodings
}

_obfuskit "$@"
