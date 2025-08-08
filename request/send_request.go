package request

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

const (
	Header     = "header"
	JSONBody   = "json_body"
	Query      = "query"
	Path       = "path"
	Form       = "form"
	Cookie     = "cookie"
	XML        = "xml"
	TextBody   = "text_body"
	BinaryBody = "binary_body"

	// Log levels
	LogLevelDebug = "DEBUG"
	LogLevelInfo  = "INFO"
	LogLevelWarn  = "WARN"
	LogLevelError = "ERROR"
)

type levelLogger struct {
	l       *log.Logger
	enabled bool
}

func (ll *levelLogger) Printf(format string, v ...interface{}) {
	if ll != nil && ll.enabled {
		ll.l.Printf(format, v...)
	}
}

func (ll *levelLogger) Println(v ...interface{}) {
	if ll != nil && ll.enabled {
		ll.l.Println(v...)
	}
}

func (ll *levelLogger) Writer() *os.File {
	// Underlying Writer may not always be *os.File; fall back to os.Stdout
	if ll == nil || ll.l == nil {
		return os.Stdout
	}
	if w, ok := ll.l.Writer().(*os.File); ok {
		return w
	}
	return os.Stdout
}

type Logger struct {
	debug *levelLogger
	info  *levelLogger
	warn  *levelLogger
	error *levelLogger
}

func NewLogger(out *os.File) *Logger { // default to ERROR
	return NewLoggerWithLevel(out, os.Getenv("OBFUSKIT_LOG_LEVEL"))
}

func NewLoggerWithLevel(out *os.File, level string) *Logger {
	// Normalize level
	lvl := strings.ToUpper(strings.TrimSpace(level))
	if lvl == "" {
		lvl = LogLevelError
	}
	enableDebug := lvl == LogLevelDebug
	enableInfo := enableDebug || lvl == LogLevelInfo
	enableWarn := enableInfo || lvl == LogLevelWarn
	// error always enabled

	return &Logger{
		debug: &levelLogger{l: log.New(out, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile), enabled: enableDebug},
		info:  &levelLogger{l: log.New(out, "[INFO] ", log.Ldate|log.Ltime|log.Lshortfile), enabled: enableInfo},
		warn:  &levelLogger{l: log.New(out, "[WARN] ", log.Ldate|log.Ltime|log.Lshortfile), enabled: enableWarn},
		error: &levelLogger{l: log.New(out, "[ERROR] ", log.Ldate|log.Ltime|log.Lshortfile), enabled: true},
	}
}

var defaultLogger = NewLogger(os.Stdout)

// normalizeURL ensures the URL has a proper scheme and explicit port
func normalizeURL(targetURL string) (string, error) {
	// Add scheme if missing
	if !strings.Contains(targetURL, "://") {
		targetURL = "http://" + targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	// Add default port if missing
	if parsedURL.Port() == "" {
		hostname := parsedURL.Hostname()
		if hostname == "" {
			return "", fmt.Errorf("invalid hostname in URL: %s", targetURL)
		}

		switch parsedURL.Scheme {
		case "http":
			parsedURL.Host = hostname + ":80"
		case "https":
			parsedURL.Host = hostname + ":443"
		default:
			parsedURL.Host = hostname + ":80"
		}
	}

	return parsedURL.String(), nil
}

type TestResult struct {
	Request          *fasthttp.Request
	Payload          string
	EvasionTechnique string
	RequestPart      string
	StatusCode       int
	ResponseTime     time.Duration
	Blocked          bool
}

func (r TestResult) String() string {
	blockedStatus := "Not Blocked"
	if r.Blocked {
		blockedStatus = "Blocked"
	}
	return fmt.Sprintf(
		"Payload: %s | Technique: %s | Part: %s | Status: %d | Time: %s | %s",
		r.Payload, r.EvasionTechnique, r.RequestPart, r.StatusCode, r.ResponseTime, blockedStatus,
	)
}

type EncodingTransformer interface {
	Name() string
	Transform(payload string) string
}

type URLEncoder struct{}

func (e *URLEncoder) Name() string {
	return "url_encoding"
}

func (e *URLEncoder) Transform(payload string) string {
	return url.QueryEscape(payload)
}

type DoubleURLEncoder struct{}

func (e *DoubleURLEncoder) Name() string {
	return "double_url_encoding"
}

func (e *DoubleURLEncoder) Transform(payload string) string {
	return url.QueryEscape(url.QueryEscape(payload))
}

type Base64Encoder struct{}

func (e *Base64Encoder) Name() string {
	return "base64_encoding"
}

func (e *Base64Encoder) Transform(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

type LineFoldingTransformer struct{}

func (e *LineFoldingTransformer) Name() string {
	return "line_folding"
}

func (e *LineFoldingTransformer) Transform(payload string) string {
	if len(payload) < 2 {
		return payload
	}

	midpoint := len(payload) / 2
	return payload[:midpoint] + "\r\n " + payload[midpoint:]
}

type FastHTTPInjector interface {
	Name() string
	Inject(targetURL string, payload string, logger *Logger) []TestResult
}

type FastHTTPHeaderInjector struct {
	transformers []EncodingTransformer
}

func NewFastHTTPHeaderInjector() *FastHTTPHeaderInjector {
	return &FastHTTPHeaderInjector{
		transformers: []EncodingTransformer{
			&URLEncoder{},
			&Base64Encoder{},
			&LineFoldingTransformer{},
		},
	}
}

func (i *FastHTTPHeaderInjector) Name() string {
	return "fasthttp_header_injection"
}

func (i *FastHTTPHeaderInjector) Inject(targetURL string, payload string, logger *Logger) []TestResult {
	results := []TestResult{}

	logger.info.Printf("Starting header injection test with payload: %s", payload)

	// Normalize the URL
	normalizedURL, err := normalizeURL(targetURL)
	if err != nil {
		logger.error.Printf("Failed to normalize URL %s: %v", targetURL, err)
		return results
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(normalizedURL)
	req.Header.Set("X-Custom-Header", payload)

	logger.debug.Printf("Sending request to %s with basic header injection", normalizedURL)
	start := time.Now()
	err = fasthttp.Do(req, resp)
	duration := time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "basic_header",
			RequestPart:      "header",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Basic header test result: %s", result.String())
	} else {
		logger.error.Printf("Basic header test failed: %v", err)
	}

	// Try different encodings for the header value
	for _, transformer := range i.transformers {
		transformedPayload := transformer.Transform(payload)

		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI(normalizedURL)
		req.Header.Set("X-Custom-Header", transformedPayload)

		logger.debug.Printf("Sending request with %s encoded header: %s", transformer.Name(), transformedPayload)
		start := time.Now()
		err := fasthttp.Do(req, resp)
		duration := time.Since(start)

		if err == nil {
			result := TestResult{
				Request:          req,
				Payload:          payload,
				EvasionTechnique: "header_" + transformer.Name(),
				RequestPart:      "header",
				StatusCode:       resp.StatusCode(),
				ResponseTime:     duration,
				Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
			}
			results = append(results, result)
			logger.info.Printf("%s header test result: %s", transformer.Name(), result.String())
		} else {
			logger.error.Printf("%s header test failed: %v", transformer.Name(), err)
		}
	}

	// Line folding evasion - manually crafting the header with line folding
	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()

	req.SetRequestURI(normalizedURL)

	// Directly set the raw header - note the \r\n with space for line folding
	if len(payload) > 2 {
		midpoint := len(payload) / 2
		foldedPayload := payload[:midpoint] + "\r\n " + payload[midpoint:]
		req.Header.SetBytesKV([]byte("X-Folded-Header"), []byte(foldedPayload))
		logger.debug.Printf("Sending request with manual line folding header: %s", foldedPayload)
	}

	start = time.Now()
	err = fasthttp.Do(req, resp)
	duration = time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "manual_line_folding",
			RequestPart:      "header",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Manual line folding test result: %s", result.String())
	} else {
		logger.error.Printf("Manual line folding test failed: %v", err)
	}

	// Multiple identical headers test
	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()

	req.SetRequestURI(normalizedURL)
	// Add header multiple times with different values
	req.Header.Add("X-Duplicate-Header", "legitimate")
	req.Header.Add("X-Duplicate-Header", payload)

	logger.debug.Printf("Sending request with duplicate headers")
	start = time.Now()
	err = fasthttp.Do(req, resp)
	duration = time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "duplicate_header",
			RequestPart:      "header",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Duplicate header test result: %s", result.String())
	} else {
		logger.error.Printf("Duplicate header test failed: %v", err)
	}

	logger.info.Printf("Completed header injection tests: %d successful, %d total", len(results), len(i.transformers)+3)
	return results
}

// FastHTTPQueryInjector injects payloads into URL query parameters
type FastHTTPQueryInjector struct {
	transformers []EncodingTransformer
}

func NewFastHTTPQueryInjector() *FastHTTPQueryInjector {
	return &FastHTTPQueryInjector{
		transformers: []EncodingTransformer{
			&URLEncoder{},
			&DoubleURLEncoder{},
		},
	}
}

func (i *FastHTTPQueryInjector) Name() string {
	return "fasthttp_query_injection"
}

func (i *FastHTTPQueryInjector) Inject(targetURL string, payload string, logger *Logger) []TestResult {
	results := []TestResult{}

	logger.info.Printf("Starting query injection test with payload: %s", payload)

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		logger.error.Printf("Failed to parse URL %s: %v", targetURL, err)
		return results
	}

	// Basic query parameter injection
	params := parsedURL.Query()
	params.Add("param", payload)
	parsedURL.RawQuery = params.Encode()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	testURL := parsedURL.String()
	req.SetRequestURI(testURL)

	logger.debug.Printf("Sending request to %s with basic query param", testURL)
	start := time.Now()
	err = fasthttp.Do(req, resp)
	duration := time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "basic_query_param",
			RequestPart:      "query",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Basic query param test result: %s", result.String())
	} else {
		logger.error.Printf("Basic query param test failed: %v", err)
	}

	// Duplicate parameter test
	parsedURL, _ = url.Parse(targetURL)
	params = parsedURL.Query()
	params.Add("param", "legitimate")
	params.Add("param", payload)
	parsedURL.RawQuery = params.Encode()

	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()

	testURL = parsedURL.String()
	req.SetRequestURI(testURL)

	logger.debug.Printf("Sending request to %s with duplicate query params", testURL)
	start = time.Now()
	err = fasthttp.Do(req, resp)
	duration = time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "duplicate_query_param",
			RequestPart:      "query",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Duplicate query param test result: %s", result.String())
	} else {
		logger.error.Printf("Duplicate query param test failed: %v", err)
	}

	logger.info.Printf("Completed query injection tests: %d successful, %d total", len(results), 2)
	return results
}

// FastHTTPBodyInjector injects payloads into request bodies
type FastHTTPBodyInjector struct {
	transformers []EncodingTransformer
}

func NewFastHTTPBodyInjector() *FastHTTPBodyInjector {
	return &FastHTTPBodyInjector{
		transformers: []EncodingTransformer{
			&URLEncoder{},
			&Base64Encoder{},
		},
	}
}

func (i *FastHTTPBodyInjector) Name() string {
	return "fasthttp_body_injection"
}

func (i *FastHTTPBodyInjector) Inject(targetURL string, payload string, logger *Logger) []TestResult {
	results := []TestResult{}

	logger.info.Printf("Starting body injection test with payload: %s", payload)

	// Normalize the URL
	normalizedURL, err := normalizeURL(targetURL)
	if err != nil {
		logger.error.Printf("Failed to normalize URL %s: %v", targetURL, err)
		return results
	}

	// Basic form parameter injection
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	formBody := fmt.Sprintf("param=%s", payload)
	req.SetRequestURI(normalizedURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBodyString(formBody)

	logger.debug.Printf("Sending POST request with form body: %s", formBody)
	start := time.Now()
	err = fasthttp.Do(req, resp)
	duration := time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "basic_form_param",
			RequestPart:      "body",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Basic form param test result: %s", result.String())
	} else {
		logger.error.Printf("Basic form param test failed: %v", err)
	}

	// JSON parameter injection
	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()

	jsonBody := fmt.Sprintf(`{"param": "%s"}`, strings.ReplaceAll(payload, `"`, `\"`))
	req.SetRequestURI(normalizedURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBodyString(jsonBody)

	logger.debug.Printf("Sending POST request with JSON body: %s", jsonBody)
	start = time.Now()
	err = fasthttp.Do(req, resp)
	duration = time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "basic_json_param",
			RequestPart:      "body",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Basic JSON param test result: %s", result.String())
	} else {
		logger.error.Printf("Basic JSON param test failed: %v", err)
	}

	// Duplicate form parameter
	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()

	duplicateFormBody := fmt.Sprintf("param=legitimate&param=%s", payload)
	req.SetRequestURI(normalizedURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBodyString(duplicateFormBody)

	logger.debug.Printf("Sending POST request with duplicate form params: %s", duplicateFormBody)
	start = time.Now()
	err = fasthttp.Do(req, resp)
	duration = time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "duplicate_form_param",
			RequestPart:      "body",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Duplicate form param test result: %s", result.String())
	} else {
		logger.error.Printf("Duplicate form param test failed: %v", err)
	}

	// Content-type mismatch evasion
	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()

	req.SetRequestURI(normalizedURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBodyString(fmt.Sprintf(`{"param": "%s"}`, strings.ReplaceAll(payload, `"`, `\"`)))

	logger.debug.Printf("Sending POST request with content-type mismatch")
	start = time.Now()
	err = fasthttp.Do(req, resp)
	duration = time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "content_type_mismatch",
			RequestPart:      "body",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Content-type mismatch test result: %s", result.String())
	} else {
		logger.error.Printf("Content-type mismatch test failed: %v", err)
	}

	logger.info.Printf("Completed body injection tests: %d successful, %d total", len(results), 4)
	return results
}

type FastHTTPProtocolInjector struct{}

func NewFastHTTPProtocolInjector() *FastHTTPProtocolInjector {
	return &FastHTTPProtocolInjector{}
}

func (i *FastHTTPProtocolInjector) Name() string {
	return "fasthttp_protocol_injection"
}

func (i *FastHTTPProtocolInjector) Inject(targetURL string, payload string, logger *Logger) []TestResult {
	results := []TestResult{}

	logger.info.Printf("Starting protocol injection test with payload: %s", payload)

	// Normalize the URL
	normalizedURL, err := normalizeURL(targetURL)
	if err != nil {
		logger.error.Printf("Failed to normalize URL %s: %v", targetURL, err)
		return results
	}

	// Test with unusual HTTP methods
	unusualMethods := []string{"TRACE", "PATCH", "PROPFIND", "CONNECT"}
	for _, method := range unusualMethods {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.SetRequestURI(normalizedURL)
		req.Header.SetMethod(method)
		req.Header.Set("X-Payload", payload)

		logger.debug.Printf("Sending %s request with payload in X-Payload header", method)
		start := time.Now()
		err = fasthttp.Do(req, resp)
		duration := time.Since(start)

		if err == nil {
			result := TestResult{
				Request:          req,
				Payload:          payload,
				EvasionTechnique: "unusual_http_method_" + method,
				RequestPart:      "method",
				StatusCode:       resp.StatusCode(),
				ResponseTime:     duration,
				Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
			}
			results = append(results, result)
			logger.info.Printf("Unusual HTTP method %s test result: %s", method, result.String())
		} else {
			logger.error.Printf("Unusual HTTP method %s test failed: %v", method, err)
		}
	}

	// Line folding in HTTP request header
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	req.SetRequestURI(normalizedURL)

	// Set a raw header with line folding
	headerName := "X-Custom-Header"
	headerValue := "part1\r\n part2" + payload
	req.Header.SetBytesKV([]byte(headerName), []byte(headerValue))

	logger.debug.Printf("Sending request with header line folding: %s", headerValue)
	start := time.Now()
	err = fasthttp.Do(req, resp)
	duration := time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "header_line_folding",
			RequestPart:      "header",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Header line folding test result: %s", result.String())
	} else {
		logger.error.Printf("Header line folding test failed: %v", err)
	}

	// Chunked encoding evasion
	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()

	req.SetRequestURI(normalizedURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Transfer-Encoding", "chunked")

	chunkData := fmt.Sprintf("param=%s", payload)
	chunkSize := fmt.Sprintf("%x", len(chunkData))
	chunkedBody := chunkSize + "\r\n" + chunkData + "\r\n0\r\n\r\n"

	req.SetBodyString(chunkedBody)

	logger.debug.Printf("Sending chunked encoding request with body: %s", chunkedBody)
	start = time.Now()
	err = fasthttp.Do(req, resp)
	duration = time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "chunked_encoding",
			RequestPart:      "body",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Chunked encoding test result: %s", result.String())
	} else {
		logger.error.Printf("Chunked encoding test failed: %v", err)
	}

	req = fasthttp.AcquireRequest()
	resp = fasthttp.AcquireResponse()

	req.SetRequestURI(normalizedURL)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	bodyContent := fmt.Sprintf("param=%s", payload)
	req.SetBodyString(bodyContent)

	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyContent)))
	req.Header.Add("Content-Length", fmt.Sprintf("%d", len(bodyContent)+10))

	logger.debug.Printf("Sending request with multiple content-length headers")
	start = time.Now()
	err = fasthttp.Do(req, resp)
	duration = time.Since(start)

	if err == nil {
		result := TestResult{
			Request:          req,
			Payload:          payload,
			EvasionTechnique: "multiple_content_length",
			RequestPart:      "header",
			StatusCode:       resp.StatusCode(),
			ResponseTime:     duration,
			Blocked:          resp.StatusCode() == 403 || resp.StatusCode() == 429,
		}
		results = append(results, result)
		logger.info.Printf("Multiple content-length headers test result: %s", result.String())
	} else {
		logger.error.Printf("Multiple content-length headers test failed: %v", err)
	}

	logger.info.Printf("Completed protocol injection tests: %d successful, %d total", len(results), len(unusualMethods)+3)
	return results
}

func loadPayloads(filename string, logger *Logger) ([]string, error) {
	logger.info.Printf("Loading payloads from file: %s", filename)

	file, err := os.Open(filename)
	if err != nil {
		logger.error.Printf("Failed to open payload file: %v", err)
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		payload := scanner.Text()
		payloads = append(payloads, payload)
		count++

		// Log every 100 payloads to avoid excessive logging
		if count%100 == 0 {
			logger.debug.Printf("Loaded %d payloads so far", count)
		}
	}

	if err := scanner.Err(); err != nil {
		logger.error.Printf("Error scanning payload file: %v", err)
		return payloads, err
	}

	logger.info.Printf("Successfully loaded %d payloads", len(payloads))
	return payloads, nil
}

func ConfigureLogging(logFile string, logLevel string) (*Logger, error) {
	var logger *Logger

	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logger = NewLogger(file)
	} else {
		logger = NewLogger(os.Stdout)
	}

	return logger, nil
}

func SendRequestsFromPayloadFile(payloadFile string, targetURL string, logFile string, logLevel string) {
	logger, err := ConfigureLogging(logFile, logLevel)
	if err != nil {
		fmt.Printf("Error setting up logging: %v\n", err)
		return
	}

	logger.info.Printf("Starting payload testing against %s", targetURL)

	payloads, err := loadPayloads(payloadFile, logger)
	if err != nil {
		logger.error.Printf("Error loading payloads: %v", err)
		return
	}

	SendRequests(payloads, targetURL, logger)
}

func SendRequests(payloads []string, targetURL string, logger *Logger) {
	if logger == nil {
		logger = defaultLogger
	}

	startTime := time.Now()
	logger.info.Printf("Starting testing of %d payloads against %s", len(payloads), targetURL)

	injectors := []FastHTTPInjector{
		NewFastHTTPHeaderInjector(),
		NewFastHTTPQueryInjector(),
		NewFastHTTPBodyInjector(),
		NewFastHTTPProtocolInjector(),
	}

	var allResults []TestResult
	totalTests := 0
	blockedTests := 0

	for payloadIndex, payload := range payloads {
		logger.info.Printf("Testing payload %d/%d: %s", payloadIndex+1, len(payloads), payload)

		for _, injector := range injectors {
			logger.debug.Printf("Using injector: %s", injector.Name())
			results := injector.Inject(targetURL, payload, logger)
			allResults = append(allResults, results...)

			totalTests += len(results)
			for _, result := range results {
				if result.Blocked {
					blockedTests++
				}
			}
		}

		// Log progress every 10 payloads
		if (payloadIndex+1)%10 == 0 || payloadIndex == len(payloads)-1 {
			logger.info.Printf("Progress: %d/%d payloads tested (%.1f%%), %d/%d tests blocked",
				payloadIndex+1, len(payloads),
				float64(payloadIndex+1)/float64(len(payloads))*100,
				blockedTests, totalTests,
			)
		}
	}

	duration := time.Since(startTime)
	logger.info.Printf("Testing completed in %s", duration)
	logger.info.Printf("Summary: %d payloads tested, %d tests executed, %d tests blocked (%.1f%%)",
		len(payloads), totalTests, blockedTests, float64(blockedTests)/float64(totalTests)*100)
}

type Option func(*TestConfig)

type TestConfig struct {
	TargetURL      string
	PayloadFile    string
	Payloads       []string
	LogFile        string
	LogLevel       string
	OutputFormat   string
	RequestTimeout time.Duration
	Concurrency    int
}

func DefaultConfig() *TestConfig {
	return &TestConfig{
		LogLevel:       LogLevelError,
		OutputFormat:   "text",
		RequestTimeout: 10 * time.Second,
		Concurrency:    5,
	}
}

func WithTargetURL(url string) Option {
	return func(c *TestConfig) {
		c.TargetURL = url
	}
}

func WithPayloadFile(file string) Option {
	return func(c *TestConfig) {
		c.PayloadFile = file
	}
}

func WithPayloads(payloads []string) Option {
	return func(c *TestConfig) {
		c.Payloads = payloads
	}
}

func WithLogFile(file string) Option {
	return func(c *TestConfig) {
		c.LogFile = file
	}
}

func WithLogLevel(level string) Option {
	return func(c *TestConfig) {
		c.LogLevel = level
	}
}

func WithOutputFormat(format string) Option {
	return func(c *TestConfig) {
		c.OutputFormat = format
	}
}

func WithRequestTimeout(timeout time.Duration) Option {
	return func(c *TestConfig) {
		c.RequestTimeout = timeout
	}
}

func WithConcurrency(n int) Option {
	return func(c *TestConfig) {
		c.Concurrency = n
	}
}

func RunTests(options ...Option) ([]TestResult, error) {
	config := DefaultConfig()

	for _, option := range options {
		option(config)
	}

	logger, err := ConfigureLogging(config.LogFile, config.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to configure logging: %v", err)
	}

	logger.info.Printf("Starting test run with config: target=%s, logLevel=%s, timeout=%s, concurrency=%d",
		config.TargetURL, config.LogLevel, config.RequestTimeout, config.Concurrency)

	var payloads []string
	if len(config.Payloads) > 0 {
		payloads = config.Payloads
		logger.info.Printf("Using %d provided payloads", len(payloads))
	} else if config.PayloadFile != "" {
		loadedPayloads, err := loadPayloads(config.PayloadFile, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to load payloads: %v", err)
		}
		payloads = loadedPayloads
	} else {
		return nil, fmt.Errorf("no payloads provided")
	}

	var allResults []TestResult

	if config.Concurrency <= 1 {
		logger.info.Printf("Running tests sequentially for %d payloads", len(payloads))
		allResults = runSequentialTests(payloads, config.TargetURL, logger)
	} else {
		logger.info.Printf("Running tests concurrently with %d workers for %d payloads",
			config.Concurrency, len(payloads))
		allResults = runConcurrentTests(payloads, config.TargetURL, config.Concurrency, logger)
	}

	blocked := 0
	for _, result := range allResults {
		if result.Blocked {
			blocked++
		}
	}

	logger.info.Printf("Test run complete: %d total tests, %d blocked (%.1f%%)",
		len(allResults), blocked, float64(blocked)/float64(len(allResults))*100)

	return allResults, nil
}

func runSequentialTests(payloads []string, targetURL string, logger *Logger) []TestResult {
	injectors := []FastHTTPInjector{
		NewFastHTTPHeaderInjector(),
		NewFastHTTPQueryInjector(),
		NewFastHTTPBodyInjector(),
		NewFastHTTPProtocolInjector(),
	}

	var allResults []TestResult
	totalPayloads := len(payloads)

	for i, payload := range payloads {
		logger.info.Printf("Testing payload %d/%d: %s", i+1, totalPayloads, payload)

		for _, injector := range injectors {
			results := injector.Inject(targetURL, payload, logger)
			allResults = append(allResults, results...)
		}

		if (i+1)%10 == 0 || i == totalPayloads-1 {
			logger.info.Printf("Progress: %d/%d payloads (%.1f%%)",
				i+1, totalPayloads, float64(i+1)/float64(totalPayloads)*100)
		}
	}

	return allResults
}

func runConcurrentTests(payloads []string, targetURL string, concurrency int, logger *Logger) []TestResult {
	jobs := make(chan string, len(payloads))
	results := make(chan []TestResult, len(payloads))

	for w := 1; w <= concurrency; w++ {
		go worker(w, jobs, results, targetURL, logger)
	}

	for _, payload := range payloads {
		jobs <- payload
	}
	close(jobs)

	var allResults []TestResult
	for i := 0; i < len(payloads); i++ {
		batchResults := <-results
		allResults = append(allResults, batchResults...)

		if (i+1)%10 == 0 || i == len(payloads)-1 {
			logger.info.Printf("Progress: %d/%d payloads (%.1f%%)",
				i+1, len(payloads), float64(i+1)/float64(len(payloads))*100)
		}
	}

	return allResults
}

func worker(id int, jobs <-chan string, results chan<- []TestResult, targetURL string, logger *Logger) {
	injectors := []FastHTTPInjector{
		NewFastHTTPHeaderInjector(),
		NewFastHTTPQueryInjector(),
		NewFastHTTPBodyInjector(),
		NewFastHTTPProtocolInjector(),
	}

	workerLogger := &Logger{
		debug: &levelLogger{l: log.New(logger.debug.Writer(), fmt.Sprintf("[DEBUG][Worker-%d] ", id), log.Ltime), enabled: logger.debug.enabled},
		info:  &levelLogger{l: log.New(logger.info.Writer(), fmt.Sprintf("[INFO][Worker-%d] ", id), log.Ltime), enabled: logger.info.enabled},
		warn:  &levelLogger{l: log.New(logger.warn.Writer(), fmt.Sprintf("[WARN][Worker-%d] ", id), log.Ltime), enabled: logger.warn.enabled},
		error: &levelLogger{l: log.New(logger.error.Writer(), fmt.Sprintf("[ERROR][Worker-%d] ", id), log.Ltime), enabled: true},
	}

	for payload := range jobs {
		workerLogger.debug.Printf("Processing payload: %s", payload)

		var batchResults []TestResult
		for _, injector := range injectors {
			results := injector.Inject(targetURL, payload, workerLogger)
			batchResults = append(batchResults, results...)
		}

		results <- batchResults
	}
}

func WriteResultsToFile(results []TestResult, filename string, format string, logger *Logger) error {
	logger.info.Printf("Writing %d results to %s in %s format", len(results), filename, format)

	file, err := os.Create(filename)
	if err != nil {
		logger.error.Printf("Failed to create output file: %v", err)
		return err
	}
	defer file.Close()

	switch format {
	case "csv":
		file.WriteString("Request,Payload,EvasionTechnique,RequestPart,StatusCode,ResponseTime,Blocked\n")

		for _, result := range results {
			file.WriteString(fmt.Sprintf("%s,%s,%s,%s,%d,%s,%t\n",
				result.Request.String(),
				strings.ReplaceAll(result.Payload, ",", "\\,"),
				result.EvasionTechnique,
				result.RequestPart,
				result.StatusCode,
				result.ResponseTime.String(),
				result.Blocked,
			))
		}

	case "json":
		file.WriteString("[\n")
		for i, result := range results {
			file.WriteString(fmt.Sprintf(`  {
    "request": "%s",
    "payload": "%s",
    "evasion_technique": "%s",
    "request_part": "%s",
    "status_code": %d,
    "response_time": "%s",
    "blocked": %t
  }`,
				strings.ReplaceAll(result.Request.String(), `"`, `\"`),
				strings.ReplaceAll(result.Payload, `"`, `\"`),
				result.EvasionTechnique,
				result.RequestPart,
				result.StatusCode,
				result.ResponseTime.String(),
				result.Blocked,
			))

			if i < len(results)-1 {
				file.WriteString(",\n")
			} else {
				file.WriteString("\n")
			}
		}
		file.WriteString("]\n")

	default:
		for _, result := range results {
			file.WriteString(result.String() + "\n")
		}
	}

	logger.info.Printf("Successfully wrote results to %s", filename)
	return nil
}
