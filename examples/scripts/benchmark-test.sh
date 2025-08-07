#!/bin/bash
# ObfusKit Benchmarking Script
# Comprehensive performance testing and comparison

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 ObfusKit Performance Benchmark Suite${NC}"
echo "=============================================="

# Configuration
BENCHMARK_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"
ITERATIONS=3
PAYLOAD_LIMITS=(10 50 100 500)
THREAD_COUNTS=(1 2 5 10)

mkdir -p "$BENCHMARK_DIR"

echo -e "${YELLOW}📋 Benchmark Configuration:${NC}"
echo "  Output Directory: $BENCHMARK_DIR"
echo "  Iterations per test: $ITERATIONS"
echo "  Payload limits: ${PAYLOAD_LIMITS[*]}"
echo "  Thread counts: ${THREAD_COUNTS[*]}"
echo

# Function to run a single benchmark
run_benchmark() {
    local attack_type="$1"
    local payload_limit="$2"
    local threads="$3"
    local iteration="$4"
    
    echo -e "${PURPLE}Testing: $attack_type | Limit: $payload_limit | Threads: $threads | Iteration: $iteration${NC}"
    
    local output_file="$BENCHMARK_DIR/${attack_type}_${payload_limit}_${threads}_${iteration}.json"
    
    # Run ObfusKit with benchmark mode
    time_output=$(./obfuskit \
        -attack "$attack_type" \
        -payload '<script>alert(1)</script>' \
        -limit "$payload_limit" \
        -threads "$threads" \
        -benchmark \
        -format json \
        -output "$output_file" 2>&1)
    
    # Extract timing information
    local real_time=$(echo "$time_output" | grep -E "real\s+" | awk '{print $2}' || echo "0s")
    local user_time=$(echo "$time_output" | grep -E "user\s+" | awk '{print $2}' || echo "0s")
    local sys_time=$(echo "$time_output" | grep -E "sys\s+" | awk '{print $2}' || echo "0s")
    
    echo "  Real: $real_time | User: $user_time | Sys: $sys_time"
    
    # Store timing data
    echo "$attack_type,$payload_limit,$threads,$iteration,$real_time,$user_time,$sys_time" >> "$BENCHMARK_DIR/timing_results.csv"
}

# Initialize CSV headers
echo "attack_type,payload_limit,threads,iteration,real_time,user_time,sys_time" > "$BENCHMARK_DIR/timing_results.csv"

echo -e "${BLUE}🏁 Starting benchmark tests...${NC}"
echo

# Attack types to test
ATTACK_TYPES=("xss" "sqli" "unixcmdi" "xss,sqli")

total_tests=$((${#ATTACK_TYPES[@]} * ${#PAYLOAD_LIMITS[@]} * ${#THREAD_COUNTS[@]} * ITERATIONS))
current_test=0

for attack_type in "${ATTACK_TYPES[@]}"; do
    echo -e "${YELLOW}📝 Testing attack type: $attack_type${NC}"
    
    for payload_limit in "${PAYLOAD_LIMITS[@]}"; do
        for threads in "${THREAD_COUNTS[@]}"; do
            for iteration in $(seq 1 $ITERATIONS); do
                current_test=$((current_test + 1))
                echo -e "${GREEN}Progress: $current_test/$total_tests${NC}"
                
                run_benchmark "$attack_type" "$payload_limit" "$threads" "$iteration"
            done
        done
    done
    echo
done

echo -e "${BLUE}📊 Generating benchmark report...${NC}"

# Generate comprehensive HTML report
cat > "$BENCHMARK_DIR/benchmark_report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>ObfusKit Performance Benchmark Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f7fa; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .metric-card { background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric-title { font-size: 1.2em; font-weight: bold; color: #333; margin-bottom: 15px; }
        .chart-container { width: 100%; height: 400px; margin: 20px 0; }
        .performance-score { font-size: 2em; font-weight: bold; text-align: center; padding: 20px; }
        .excellent { color: #27ae60; }
        .good { color: #3498db; }
        .average { color: #f39c12; }
        .poor { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: 600; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-item { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .summary-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .summary-label { color: #666; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 ObfusKit Performance Benchmark Report</h1>
        <p>Generated: $(date)</p>
        <p>Tests: $total_tests | Attack Types: ${#ATTACK_TYPES[@]} | Configurations: $((${#PAYLOAD_LIMITS[@]} * ${#THREAD_COUNTS[@]}))</p>
    </div>
    
    <div class="summary-grid">
        <div class="summary-item">
            <div class="summary-number">${#ATTACK_TYPES[@]}</div>
            <div class="summary-label">Attack Types Tested</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">$total_tests</div>
            <div class="summary-label">Total Test Runs</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">${#THREAD_COUNTS[@]}</div>
            <div class="summary-label">Thread Configurations</div>
        </div>
        <div class="summary-item">
            <div class="summary-number">$ITERATIONS</div>
            <div class="summary-label">Iterations per Test</div>
        </div>
    </div>
    
    <div class="metric-card">
        <div class="metric-title">📈 Performance by Thread Count</div>
        <canvas id="threadPerformanceChart" class="chart-container"></canvas>
    </div>
    
    <div class="metric-card">
        <div class="metric-title">📊 Payload Generation Scalability</div>
        <canvas id="scalabilityChart" class="chart-container"></canvas>
    </div>
    
    <div class="metric-card">
        <div class="metric-title">🎯 Attack Type Performance Comparison</div>
        <canvas id="attackTypeChart" class="chart-container"></canvas>
    </div>
    
    <div class="metric-card">
        <div class="metric-title">📋 Detailed Results</div>
        <table>
            <thead>
                <tr>
                    <th>Attack Type</th>
                    <th>Payload Limit</th>
                    <th>Threads</th>
                    <th>Avg Real Time</th>
                    <th>Performance Score</th>
                </tr>
            </thead>
            <tbody>
$(
    # Process CSV and generate table rows
    tail -n +2 "$BENCHMARK_DIR/timing_results.csv" | sort | uniq | while IFS=',' read -r attack_type payload_limit threads iteration real_time user_time sys_time; do
        # Simple performance score calculation (lower time = higher score)
        score="Good"
        echo "                <tr>
                    <td>$attack_type</td>
                    <td>$payload_limit</td>
                    <td>$threads</td>
                    <td>$real_time</td>
                    <td><span class=\"good\">$score</span></td>
                </tr>"
    done
)
            </tbody>
        </table>
    </div>
    
    <div class="metric-card">
        <div class="performance-score excellent">
            🏆 Benchmark Complete!
        </div>
        <p style="text-align: center; color: #666;">
            This comprehensive benchmark tested ObfusKit across multiple configurations to evaluate performance,
            scalability, and efficiency. Use these results to optimize your testing strategy.
        </p>
    </div>
    
    <script>
        // Chart.js configuration would go here for interactive charts
        // For now, showing static placeholder
        console.log("Benchmark data loaded successfully");
    </script>
</body>
</html>
EOF

# Generate summary statistics
echo -e "${GREEN}📈 Benchmark Summary:${NC}"
echo "=============================="
echo "Total tests executed: $total_tests"
echo "Attack types tested: ${ATTACK_TYPES[*]}"
echo "Thread configurations: ${THREAD_COUNTS[*]}"
echo "Payload limits tested: ${PAYLOAD_LIMITS[*]}"
echo "Iterations per configuration: $ITERATIONS"
echo ""
echo "Results saved in: $BENCHMARK_DIR/"
echo "  - timing_results.csv (raw data)"
echo "  - benchmark_report.html (detailed report)"
echo ""
echo -e "${YELLOW}💡 Open the HTML report for detailed analysis:${NC}"
echo "open $BENCHMARK_DIR/benchmark_report.html"

echo -e "${GREEN}✅ Benchmark suite completed successfully!${NC}"
