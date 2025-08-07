#!/bin/bash
# Enterprise Batch Testing Script
# Comprehensive WAF testing across multiple targets with advanced features

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️  ObfusKit Enterprise Batch Testing${NC}"
echo "=========================================="

# Configuration
URL_FILE="${1:-examples/urls/targets.txt}"
PAYLOAD_FILE="${2:-examples/payloads/enterprise_payloads.txt}"
THREADS="${3:-10}"
OUTPUT_DIR="batch_test_results_$(date +%Y%m%d_%H%M%S)"

echo -e "${YELLOW}📋 Configuration:${NC}"
echo "  URL File: $URL_FILE"
echo "  Payload File: $PAYLOAD_FILE"
echo "  Threads: $THREADS"
echo "  Output Directory: $OUTPUT_DIR"
echo

# Check if files exist
if [ ! -f "$URL_FILE" ]; then
    echo -e "${RED}❌ Error: URL file '$URL_FILE' not found${NC}"
    echo "Create a file with target URLs (one per line) or provide a different file path."
    exit 1
fi

if [ ! -f "$PAYLOAD_FILE" ]; then
    echo -e "${RED}❌ Error: Payload file '$PAYLOAD_FILE' not found${NC}"
    echo "Create a payload file or provide a different file path."
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}🚀 Starting enterprise batch testing...${NC}"
echo

# Test each attack type against all URLs
ATTACK_TYPES=("xss" "sqli" "unixcmdi" "path" "ldapi")

for attack_type in "${ATTACK_TYPES[@]}"; do
    echo -e "${PURPLE}🎯 Testing $attack_type attacks...${NC}"
    
    # Run ObfusKit with current attack type
    ./obfuskit \
        -attack "$attack_type" \
        -payload-file "$PAYLOAD_FILE" \
        -url-file "$URL_FILE" \
        -threads "$THREADS" \
        -progress \
        -fingerprint \
        -waf-report \
        -format json \
        -output "$OUTPUT_DIR/${attack_type}_results.json" \
        -report html \
        -complexity medium \
        -only-successful
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ $attack_type testing completed${NC}"
    else
        echo -e "${RED}❌ $attack_type testing failed${NC}"
    fi
    echo
done

# Multi-attack comprehensive test
echo -e "${PURPLE}🔄 Running comprehensive multi-attack test...${NC}"
./obfuskit \
    -attack "xss,sqli,unixcmdi" \
    -payload-file "$PAYLOAD_FILE" \
    -url-file "$URL_FILE" \
    -threads "$THREADS" \
    -progress \
    -fingerprint \
    -waf-report \
    -format json \
    -output "$OUTPUT_DIR/comprehensive_results.json" \
    -report html \
    -limit 100 \
    -min-success-rate 0.1

echo
echo -e "${BLUE}📊 Batch Testing Summary:${NC}"
echo "=========================================="
echo "Tests completed: $(date)"
echo "Results directory: $OUTPUT_DIR"
echo "Attack types tested: ${ATTACK_TYPES[*]}"
echo

# Generate summary report
echo -e "${YELLOW}📈 Generating summary report...${NC}"
cat > "$OUTPUT_DIR/summary.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>ObfusKit Enterprise Batch Test Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .result { margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; background: #f8f9fa; }
        .success { border-left-color: #27ae60; }
        .warning { border-left-color: #f39c12; }
        .error { border-left-color: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ObfusKit Enterprise Batch Test Results</h1>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="result">
        <h2>📋 Test Configuration</h2>
        <ul>
            <li><strong>URL File:</strong> $URL_FILE</li>
            <li><strong>Payload File:</strong> $PAYLOAD_FILE</li>
            <li><strong>Threads:</strong> $THREADS</li>
            <li><strong>Attack Types:</strong> ${ATTACK_TYPES[*]}</li>
        </ul>
    </div>
    
    <div class="result">
        <h2>📁 Generated Files</h2>
        <ul>
$(for attack_type in "${ATTACK_TYPES[@]}"; do
    if [ -f "$OUTPUT_DIR/${attack_type}_results.json" ]; then
        echo "            <li><a href=\"${attack_type}_results.json\">${attack_type} Results (JSON)</a></li>"
    fi
done)
            <li><a href="comprehensive_results.json">Comprehensive Results (JSON)</a></li>
        </ul>
    </div>
    
    <div class="result success">
        <h2>✅ Next Steps</h2>
        <ol>
            <li>Review individual attack type results</li>
            <li>Analyze WAF fingerprinting reports</li>
            <li>Focus on successful bypasses</li>
            <li>Update WAF rules based on findings</li>
        </ol>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✅ Summary report generated: $OUTPUT_DIR/summary.html${NC}"
echo
echo -e "${YELLOW}💡 Open the summary report in your browser:${NC}"
echo "open $OUTPUT_DIR/summary.html"
