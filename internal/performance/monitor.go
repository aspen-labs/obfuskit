package performance

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Statistics tracks comprehensive performance metrics
type Statistics struct {
	StartTime       time.Time     `json:"start_time"`
	EndTime         time.Time     `json:"end_time"`
	TotalDuration   time.Duration `json:"total_duration"`
	PayloadGenTime  time.Duration `json:"payload_generation_time"`
	RequestSendTime time.Duration `json:"request_sending_time"`
	ReportGenTime   time.Duration `json:"report_generation_time"`

	// Request statistics
	TotalRequests       int           `json:"total_requests"`
	SuccessfulRequests  int           `json:"successful_requests"`
	FailedRequests      int           `json:"failed_requests"`
	AverageResponseTime time.Duration `json:"average_response_time"`
	MinResponseTime     time.Duration `json:"min_response_time"`
	MaxResponseTime     time.Duration `json:"max_response_time"`

	// Payload statistics
	TotalPayloads     int     `json:"total_payloads"`
	TotalVariants     int     `json:"total_variants"`
	PayloadsPerSecond float64 `json:"payloads_per_second"`
	RequestsPerSecond float64 `json:"requests_per_second"`

	// Resource usage
	PeakMemoryUsage    uint64  `json:"peak_memory_usage_bytes"`
	AverageMemoryUsage uint64  `json:"average_memory_usage_bytes"`
	CPUUsagePercent    float64 `json:"cpu_usage_percent"`
	GoroutinesCount    int     `json:"goroutines_count"`

	// Threading statistics
	ThreadsUsed      int     `json:"threads_used"`
	ThreadEfficiency float64 `json:"thread_efficiency"`
	ConcurrencyLevel float64 `json:"concurrency_level"`

	mutex            sync.RWMutex
	responseTimesSum time.Duration
	memoryReadings   []uint64
}

// Monitor handles performance monitoring
type Monitor struct {
	stats     *Statistics
	startTime time.Time
	stopChan  chan bool
	wg        sync.WaitGroup
}

// NewMonitor creates a new performance monitor
func NewMonitor() *Monitor {
	return &Monitor{
		stats: &Statistics{
			StartTime:       time.Now(),
			MinResponseTime: time.Hour, // Initialize with high value
		},
		startTime: time.Now(),
		stopChan:  make(chan bool, 1),
	}
}

// Start begins performance monitoring
func (m *Monitor) Start() {
	m.stats.StartTime = time.Now()
	m.startTime = time.Now()

	// Start goroutine for memory monitoring
	m.wg.Add(1)
	go m.monitorResources()
}

// Stop ends performance monitoring and calculates final statistics
func (m *Monitor) Stop() {
	m.stats.EndTime = time.Now()
	m.stats.TotalDuration = m.stats.EndTime.Sub(m.stats.StartTime)

	// Stop resource monitoring
	close(m.stopChan)
	m.wg.Wait()

	// Calculate derived statistics
	m.calculateDerivedStats()
}

// RecordPayloadGeneration records payload generation timing
func (m *Monitor) RecordPayloadGeneration(start time.Time, payloads, variants int) {
	m.stats.mutex.Lock()
	defer m.stats.mutex.Unlock()

	m.stats.PayloadGenTime = time.Since(start)
	m.stats.TotalPayloads = payloads
	m.stats.TotalVariants = variants
}

// RecordRequestSending records request sending timing
func (m *Monitor) RecordRequestSending(start time.Time, requests int) {
	m.stats.mutex.Lock()
	defer m.stats.mutex.Unlock()

	m.stats.RequestSendTime = time.Since(start)
	m.stats.TotalRequests = requests
}

// RecordReportGeneration records report generation timing
func (m *Monitor) RecordReportGeneration(start time.Time) {
	m.stats.mutex.Lock()
	defer m.stats.mutex.Unlock()

	m.stats.ReportGenTime = time.Since(start)
}

// RecordRequest records individual request performance
func (m *Monitor) RecordRequest(responseTime time.Duration, success bool) {
	m.stats.mutex.Lock()
	defer m.stats.mutex.Unlock()

	if success {
		m.stats.SuccessfulRequests++
	} else {
		m.stats.FailedRequests++
	}

	m.stats.responseTimesSum += responseTime

	if responseTime < m.stats.MinResponseTime {
		m.stats.MinResponseTime = responseTime
	}
	if responseTime > m.stats.MaxResponseTime {
		m.stats.MaxResponseTime = responseTime
	}
}

// SetThreads records the number of threads being used
func (m *Monitor) SetThreads(threads int) {
	m.stats.mutex.Lock()
	defer m.stats.mutex.Unlock()

	m.stats.ThreadsUsed = threads
}

// GetStatistics returns a copy of current statistics
func (m *Monitor) GetStatistics() Statistics {
	m.stats.mutex.RLock()
	defer m.stats.mutex.RUnlock()

	// Create a copy to avoid race conditions
	statsCopy := *m.stats
	return statsCopy
}

// monitorResources runs in a goroutine to continuously monitor system resources
func (m *Monitor) monitorResources() {
	defer m.wg.Done()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.sampleMemoryUsage()
		}
	}
}

// sampleMemoryUsage samples current memory usage
func (m *Monitor) sampleMemoryUsage() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	m.stats.mutex.Lock()
	defer m.stats.mutex.Unlock()

	currentMemory := memStats.Alloc
	m.stats.memoryReadings = append(m.stats.memoryReadings, currentMemory)

	if currentMemory > m.stats.PeakMemoryUsage {
		m.stats.PeakMemoryUsage = currentMemory
	}

	m.stats.GoroutinesCount = runtime.NumGoroutine()
}

// calculateDerivedStats calculates derived statistics after monitoring is complete
func (m *Monitor) calculateDerivedStats() {
	m.stats.mutex.Lock()
	defer m.stats.mutex.Unlock()

	// Calculate rates
	totalSeconds := m.stats.TotalDuration.Seconds()
	if totalSeconds > 0 {
		m.stats.PayloadsPerSecond = float64(m.stats.TotalVariants) / totalSeconds
		m.stats.RequestsPerSecond = float64(m.stats.TotalRequests) / totalSeconds
	}

	// Calculate average response time
	totalRequests := m.stats.SuccessfulRequests + m.stats.FailedRequests
	if totalRequests > 0 {
		m.stats.AverageResponseTime = m.stats.responseTimesSum / time.Duration(totalRequests)
	}

	// Calculate average memory usage
	if len(m.stats.memoryReadings) > 0 {
		var sum uint64
		for _, reading := range m.stats.memoryReadings {
			sum += reading
		}
		m.stats.AverageMemoryUsage = sum / uint64(len(m.stats.memoryReadings))
	}

	// Calculate thread efficiency
	if m.stats.ThreadsUsed > 0 {
		idealTime := m.stats.TotalDuration / time.Duration(m.stats.ThreadsUsed)
		actualTime := m.stats.TotalDuration
		if actualTime > 0 {
			m.stats.ThreadEfficiency = float64(idealTime) / float64(actualTime) * 100
		}
	}

	// Calculate concurrency level
	if m.stats.RequestSendTime > 0 && m.stats.TotalRequests > 0 {
		avgRequestTime := m.stats.AverageResponseTime
		if avgRequestTime > 0 {
			m.stats.ConcurrencyLevel = float64(m.stats.RequestSendTime) / float64(avgRequestTime*time.Duration(m.stats.TotalRequests))
		}
	}
}

// FormatStatistics returns a human-readable performance report
func (m *Monitor) FormatStatistics() string {
	stats := m.GetStatistics()

	report := fmt.Sprintf(`
🚀 PERFORMANCE STATISTICS
=========================
📊 Execution Overview:
  Total Duration: %v
  Start Time: %s
  End Time: %s

⚡ Processing Performance:
  Payload Generation: %v
  Request Sending: %v
  Report Generation: %v

🎯 Payload Statistics:
  Total Base Payloads: %d
  Total Variants Generated: %d
  Generation Rate: %.1f payloads/sec

🌐 Request Statistics:
  Total Requests: %d
  Successful Requests: %d
  Failed Requests: %d
  Success Rate: %.1f%%
  Request Rate: %.1f requests/sec

⏱️ Response Time Analysis:
  Average Response Time: %v
  Minimum Response Time: %v
  Maximum Response Time: %v

🧠 Resource Utilization:
  Peak Memory Usage: %s
  Average Memory Usage: %s
  Active Goroutines: %d

🔧 Threading Performance:
  Threads Used: %d
  Thread Efficiency: %.1f%%
  Concurrency Level: %.2f

💡 Performance Score: %s
`,
		stats.TotalDuration,
		stats.StartTime.Format("15:04:05"),
		stats.EndTime.Format("15:04:05"),

		stats.PayloadGenTime,
		stats.RequestSendTime,
		stats.ReportGenTime,

		stats.TotalPayloads,
		stats.TotalVariants,
		stats.PayloadsPerSecond,

		stats.TotalRequests,
		stats.SuccessfulRequests,
		stats.FailedRequests,
		calculateSuccessRate(stats.SuccessfulRequests, stats.TotalRequests),
		stats.RequestsPerSecond,

		stats.AverageResponseTime,
		stats.MinResponseTime,
		stats.MaxResponseTime,

		formatBytes(stats.PeakMemoryUsage),
		formatBytes(stats.AverageMemoryUsage),
		stats.GoroutinesCount,

		stats.ThreadsUsed,
		stats.ThreadEfficiency,
		stats.ConcurrencyLevel,

		calculatePerformanceScore(stats),
	)

	return report
}

// Helper functions
func calculateSuccessRate(successful, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(successful) / float64(total) * 100
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func calculatePerformanceScore(stats Statistics) string {
	score := 0.0

	// Rate scoring (30% weight)
	if stats.RequestsPerSecond > 100 {
		score += 30
	} else if stats.RequestsPerSecond > 50 {
		score += 20
	} else if stats.RequestsPerSecond > 10 {
		score += 10
	}

	// Efficiency scoring (25% weight)
	if stats.ThreadEfficiency > 80 {
		score += 25
	} else if stats.ThreadEfficiency > 60 {
		score += 15
	} else if stats.ThreadEfficiency > 40 {
		score += 10
	}

	// Memory efficiency scoring (20% weight)
	if stats.PeakMemoryUsage < 100*1024*1024 { // < 100MB
		score += 20
	} else if stats.PeakMemoryUsage < 500*1024*1024 { // < 500MB
		score += 15
	} else if stats.PeakMemoryUsage < 1024*1024*1024 { // < 1GB
		score += 10
	}

	// Response time scoring (25% weight)
	avgMs := float64(stats.AverageResponseTime.Nanoseconds()) / 1e6
	if avgMs < 100 {
		score += 25
	} else if avgMs < 500 {
		score += 15
	} else if avgMs < 1000 {
		score += 10
	}

	// Determine rating
	if score >= 80 {
		return fmt.Sprintf("🏆 EXCELLENT (%.0f/100)", score)
	} else if score >= 60 {
		return fmt.Sprintf("🥈 GOOD (%.0f/100)", score)
	} else if score >= 40 {
		return fmt.Sprintf("🥉 AVERAGE (%.0f/100)", score)
	} else {
		return fmt.Sprintf("⚠️ NEEDS IMPROVEMENT (%.0f/100)", score)
	}
}
