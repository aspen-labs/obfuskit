#!/bin/bash
# Bash completion for obfuskit

_obfuskit_completion() {
    local cur prev opts attack_types encodings levels reports formats
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main options
    opts="-help -config -generate-config -server -attack -payload -payload-file -url -url-file -output -level -encoding -report -threads -format -progress -limit -min-success-rate -complexity -max-response-time -filter-status -exclude-encodings -only-successful -fingerprint -waf-report"
    
    # Attack types
    attack_types="xss sqli sql unixcmdi unix wincmdi windows oscmdi os path fileaccess file ldapi ldap ssrf xxe generic all"
    
    # Encoding methods
    encodings="url doubleurl double-url html unicode base64 b64 hex octal bestfit best-fit mixedcase mixed-case utf8 utf-8 unixcmd unix-cmd windowscmd windows-cmd pathtraversal path-traversal"
    
    # Evasion levels
    levels="basic medium advanced"
    
    # Report formats
    reports="pretty terminal html pdf csv nuclei json auto all"
    
    # Output formats
    formats="text json csv"

    case ${prev} in
        -attack)
            COMPREPLY=( $(compgen -W "${attack_types}" -- ${cur}) )
            return 0
            ;;
        -level)
            COMPREPLY=( $(compgen -W "${levels}" -- ${cur}) )
            return 0
            ;;
        -encoding)
            COMPREPLY=( $(compgen -W "${encodings}" -- ${cur}) )
            return 0
            ;;
        -report)
            COMPREPLY=( $(compgen -W "${reports}" -- ${cur}) )
            return 0
            ;;
        -format)
            COMPREPLY=( $(compgen -W "${formats}" -- ${cur}) )
            return 0
            ;;
        -generate-config)
            COMPREPLY=( $(compgen -W "yaml json" -- ${cur}) )
            return 0
            ;;
        -config|-payload-file|-url-file|-output)
            # File completion
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
        -url)
            # URL completion - provide some examples
            COMPREPLY=( $(compgen -W "http:// https://" -- ${cur}) )
            return 0
            ;;
        -threads|-limit)
            # Number completion
            COMPREPLY=( $(compgen -W "1 2 4 5 8 10" -- ${cur}) )
            return 0
            ;;
        -complexity)
            COMPREPLY=( $(compgen -W "simple medium complex" -- ${cur}) )
            return 0
            ;;
        -min-success-rate)
            COMPREPLY=( $(compgen -W "0.1 0.2 0.5 0.8" -- ${cur}) )
            return 0
            ;;
        -max-response-time)
            COMPREPLY=( $(compgen -W "1s 2s 5s 10s 500ms" -- ${cur}) )
            return 0
            ;;
        -filter-status)
            COMPREPLY=( $(compgen -W "200 404 403 500 200,404" -- ${cur}) )
            return 0
            ;;
        -exclude-encodings)
            COMPREPLY=( $(compgen -W "base64 hex unicode url html" -- ${cur}) )
            return 0
            ;;
    esac

    # Default completion
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}

# Register the completion function
complete -F _obfuskit_completion obfuskit
