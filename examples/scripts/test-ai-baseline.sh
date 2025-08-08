#!/bin/bash

# AI Integration with Baseline Context Test Script
# This script demonstrates how to use ObfusKit with AI-powered payload generation
# and baseline request/response context for enhanced evasion

set -e

echo "🤖 ObfusKit AI Baseline Context Test"
echo "====================================="

# Check if OpenAI API key is set
if [ -z "$OPENAI_API_KEY" ]; then
    echo "⚠️  Warning: OPENAI_API_KEY not set. AI features will be disabled."
    echo "   Set OPENAI_API_KEY environment variable to enable AI features."
    echo "   Example: export OPENAI_API_KEY='your-api-key-here'"
    echo ""
fi

# Test 1: Basic AI payload generation
echo "🧪 Test 1: Basic AI Payload Generation"
echo "---------------------------------------"
./obfuskit \
    -attack xss \
    -payload "<script>alert('test')</script>" \
    -url "https://httpbin.org/anything" \
    -ai \
    -ai-provider openai \
    -ai-model gpt-4 \
    -ai-count 5 \
    -ai-creativity 0.7 \
    -format json \
    -progress

echo ""
echo "✅ Test 1 completed"
echo ""

# Test 2: AI with baseline context
echo "🧪 Test 2: AI with Baseline Context"
echo "-----------------------------------"
./obfuskit \
    -attack xss \
    -payload "<script>alert('test')</script>" \
    -url "https://httpbin.org/anything" \
    -ai \
    -ai-provider openai \
    -ai-model gpt-4 \
    -ai-count 5 \
    -ai-creativity 0.8 \
    -ai-context "REQUEST_BASELINE: POST /api/search HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nquery=user_input&filter=active\n\nRESPONSE_BASELINE: HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"results\": [{\"id\": 1, \"name\": \"test\"}]}" \
    -format json \
    -progress

echo ""
echo "✅ Test 2 completed"
echo ""

# Test 3: AI with configuration file
echo "🧪 Test 3: AI with Configuration File"
echo "------------------------------------"
if [ -f "examples/configs/ai_baseline_context.yaml" ]; then
    ./obfuskit \
        -config examples/configs/ai_baseline_context.yaml \
        -format json \
        -progress
else
    echo "⚠️  Configuration file not found. Skipping test 3."
fi

echo ""
echo "✅ Test 3 completed"
echo ""

# Test 4: AI with WAF fingerprinting
echo "🧪 Test 4: AI with WAF Fingerprinting"
echo "-------------------------------------"
./obfuskit \
    -attack sqli \
    -payload "' OR 1=1--" \
    -url "https://httpbin.org/anything" \
    -ai \
    -ai-provider openai \
    -ai-model gpt-4 \
    -ai-count 3 \
    -fingerprint \
    -show-waf-report \
    -format json \
    -progress

echo ""
echo "✅ Test 4 completed"
echo ""

# Test 5: AI with multiple attack types
echo "🧪 Test 5: AI with Multiple Attack Types"
echo "----------------------------------------"
./obfuskit \
    -attack xss,sqli \
    -payload "<script>alert('test')</script>" \
    -url "https://httpbin.org/anything" \
    -ai \
    -ai-provider openai \
    -ai-model gpt-4 \
    -ai-count 3 \
    -ai-creativity 0.9 \
    -format json \
    -progress

echo ""
echo "✅ Test 5 completed"
echo ""

echo "🎉 All AI Baseline Context Tests Completed!"
echo ""
echo "📊 Summary:"
echo "  - Test 1: Basic AI generation"
echo "  - Test 2: AI with baseline context"
echo "  - Test 3: AI with config file"
echo "  - Test 4: AI with WAF fingerprinting"
echo "  - Test 5: AI with multiple attack types"
echo ""
echo "💡 Tips:"
echo "  - Set OPENAI_API_KEY for full AI functionality"
echo "  - Use -ai-context to provide baseline request/response data"
echo "  - Combine with -fingerprint for WAF-aware generation"
echo "  - Use -ai-creativity to control AI creativity level"
echo ""
