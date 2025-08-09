package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed static/*
var embeddedStatic embed.FS

func main() {
	mux := http.NewServeMux()

	// Basic routes
	mux.HandleFunc("/", withLogging(indexHandler))
	mux.HandleFunc("/echo", withLogging(echoHandler))
	mux.HandleFunc("/decode", withLogging(decodeHandler))
	mux.HandleFunc("/normalize", withLogging(normalizeHandler))
	mux.HandleFunc("/path", withLogging(pathHandler))
	mux.HandleFunc("/pathwin", withLogging(pathWindowsHandler))
	mux.HandleFunc("/json", withLogging(jsonHandler))
	mux.HandleFunc("/xml", withLogging(xmlHandler))
	mux.HandleFunc("/mime", withLogging(mimeSniffHandler))
	mux.HandleFunc("/filter", withLogging(filterHandler))
	mux.HandleFunc("/xss", withLogging(xssHandler))
	mux.HandleFunc("/headers", withLogging(headersHandler))
	mux.HandleFunc("/cookies", withLogging(cookiesHandler))
	mux.HandleFunc("/nullbyte", withLogging(nullByteHandler))
	mux.HandleFunc("/hpp", withLogging(hppHandler))
	mux.HandleFunc("/semicolon", withLogging(semicolonHandler))
	mux.HandleFunc("/upload", withLogging(uploadHandler))
	mux.HandleFunc("/methods", withLogging(methodsHandler))
	mux.HandleFunc("/chain", withLogging(chainHandler))
	mux.HandleFunc("/proxy", withLogging(proxyTrustHandler))
	mux.HandleFunc("/desync", withLogging(desyncEchoHandler))
	mux.HandleFunc("/case", withLogging(caseSensitivityHandler))

	// UI: serve embedded static files under /ui/
	uiFS, _ := fs.Sub(embeddedStatic, "static")
	mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(uiFS))))
	mux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	srv := &http.Server{
		Addr:              ":8881",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("obfuskitvulnapp listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// withLogging logs a sanitized view, but handlers operate on raw to demonstrate mismatches
func withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Create a sanitized copy for logging only
		sanitizedQuery := url.Values{}
		for k, vs := range r.URL.Query() {
			cleaned := make([]string, 0, len(vs))
			for _, v := range vs {
				v = strings.ReplaceAll(v, "\n", "\\n")
				v = strings.ReplaceAll(v, "\r", "\\r")
				if len(v) > 256 {
					v = v[:256] + "…"
				}
				cleaned = append(cleaned, v)
			}
			sanitizedQuery[k] = cleaned
		}
		next(w, r)
		log.Printf("%s %s %dms query=%s ua=%q", r.Method, r.URL.Path, time.Since(start).Milliseconds(), sanitizedQuery.Encode(), r.UserAgent())
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "obfuskitvulnapp: intentionally vulnerable normalization playground\n")
	fmt.Fprintf(w, "See README for endpoints.\n")
}

// /echo?q=...
// Reflects input with optional enc parameter controlling pre/post decoding
func echoHandler(w http.ResponseWriter, r *http.Request) {
	q := getRawParam(r, "q")
	enc := r.URL.Query().Get("enc") // e.g., url,b64,hex,html,octal,unicode
	order := strings.Split(enc, ",")
	val := q
	for _, step := range order {
		step = strings.TrimSpace(strings.ToLower(step))
		if step == "" {
			continue
		}
		v, _ := decodeOnce(step, val)
		val = v
	}
	// Intentionally reflect without HTML escaping if mode=raw
	mode := r.URL.Query().Get("mode")
	if strings.EqualFold(mode, "raw") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "%s", val)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%s", val)
}

// /decode?mode=b64|url|hex|html|octal|unicode&value=...&repeat=2
func decodeHandler(w http.ResponseWriter, r *http.Request) {
	mode := strings.ToLower(r.URL.Query().Get("mode"))
	repeat, _ := strconv.Atoi(r.URL.Query().Get("repeat"))
	if repeat <= 0 {
		repeat = 1
	}
	input := getRawParam(r, "value")
	val := input
	for i := 0; i < repeat; i++ {
		v, err := decodeOnce(mode, val)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		val = v
	}
	fmt.Fprint(w, val)
}

// /normalize?u=... Demonstrates inconsistent URL normalization
func normalizeHandler(w http.ResponseWriter, r *http.Request) {
	raw := getRawParam(r, "u")
	// Wrong order: cleaning before decoding
	cleanedBefore := path.Clean(raw)
	// Better order: decode then clean (but we still show both)
	decoded, _ := url.QueryUnescape(raw)
	cleanedAfter := path.Clean(decoded)
	fmt.Fprintf(w, "raw=%q\ncleanedBefore=%q\ndecoded=%q\ncleanedAfter=%q\n", raw, cleanedBefore, decoded, cleanedAfter)
}

// /path?file=... Demonstrates path normalization discrepancies and double decoding
func pathHandler(w http.ResponseWriter, r *http.Request) {
	baseDir := filepath.Join(".", "files")
	raw := getRawParam(r, "file")
	// Double decode bug
	d1, _ := url.QueryUnescape(raw)
	d2, _ := url.QueryUnescape(d1)
	// Wrong normalization: clean the raw and join
	wrongPath := filepath.Join(baseDir, filepath.Clean(raw))
	// Another variant: clean after double decode
	rightish := filepath.Join(baseDir, filepath.Clean(d2))
	// Intentionally use the unsafe path for reading to demonstrate traversal
	data, err := os.ReadFile(wrongPath)
	if err != nil {
		fmt.Fprintf(w, "error reading (unsafe) %q: %v\n", wrongPath, err)
	} else {
		fmt.Fprintf(w, "(unsafe) %s\n", string(data))
	}
	fmt.Fprintf(w, "unsafe=%q\nsafer=%q\n", wrongPath, rightish)
}

// /pathwin?file=..\\..\\windows.txt — demonstrate backslash confusion
func pathWindowsHandler(w http.ResponseWriter, r *http.Request) {
	baseDir := filepath.Join(".", "files")
	raw := getRawParam(r, "file")
	// Vulnerable normalization: convert backslashes to current OS separator BEFORE cleaning
	// This enables traversal using backslashes on UNIX
	converted := strings.ReplaceAll(raw, "\\", string(os.PathSeparator))
	p := filepath.Join(baseDir, filepath.Clean(converted))
	data, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(w, "error reading %q: %v\n", p, err)
		return
	}
	fmt.Fprintf(w, "%s", data)
}

// /json accepts JSON, but falls back to permissive parsing with case confusion
func jsonHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ct := r.Header.Get("Content-Type")
	// Case sensitivity confusion in keys
	prefer := r.Header.Get("X-JSON-Case") // e.g., upper, lower, original
	values := map[string]any{}
	if strings.Contains(strings.ToLower(ct), "json") {
		// Extremely loose JSON parse: split on punctuation
		tokens := splitLoose(string(body))
		for i := 0; i+1 < len(tokens); i += 2 {
			k, v := tokens[i], tokens[i+1]
			k = applyCase(prefer, k)
			values[k] = v
		}
	} else {
		// Misparsed: treat body as querystring if not json
		q, _ := url.ParseQuery(string(body))
		for k, vs := range q {
			k = applyCase(prefer, k)
			if len(vs) == 1 {
				values[k] = vs[0]
			} else {
				values[k] = vs
			}
		}
	}
	// HTTP parameter pollution: merge URL query (favoring last writer)
	for k, vs := range r.URL.Query() {
		k = applyCase(prefer, k)
		if len(vs) > 0 {
			values[k] = vs[len(vs)-1]
		}
	}
	// Reflect unsafely if mode=raw
	if strings.EqualFold(r.URL.Query().Get("mode"), "raw") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		for k, v := range values {
			fmt.Fprintf(w, "%s=%v\n", k, v)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Build naive JSON by string concatenation to keep it intentionally flawed
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:%q", k, fmt.Sprint(values[k]))
	}
	b.WriteString("}")
	fmt.Fprint(w, b.String())
}

// /mime demonstrates mime sniffing over declared types
func mimeSniffHandler(w http.ResponseWriter, r *http.Request) {
	var body []byte
	// Accept multipart or raw
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(ct), "multipart/") {
		mr, err := r.MultipartReader()
		if err == nil {
			for {
				part, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}
				if part.FileName() != "" {
					data, _ := io.ReadAll(part)
					body = data
					break
				}
			}
		}
	} else {
		body, _ = io.ReadAll(r.Body)
	}
	declared := ct
	sniffed := http.DetectContentType(body)
	// Prefer sniffed over declared (vulnerable behavior)
	fmt.Fprintf(w, "declared=%q\nsniffed=%q\n", declared, sniffed)
	if strings.Contains(sniffed, "text/html") {
		// Dangerous: treat any sniffed HTML as trusted and render it
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "%s", body)
		return
	}
	w.Header().Set("Content-Type", sniffed)
	w.Write(body)
}

// /cookies?name=SESSION&pick=last — cookie parsing ambiguities
func cookiesHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "session"
	}
	pick := strings.ToLower(r.URL.Query().Get("pick")) // first|last
	all := r.Cookies()
	var values []string
	for _, c := range all {
		if strings.EqualFold(c.Name, name) {
			values = append(values, c.Value)
		}
	}
	fmt.Fprintf(w, "all=%q\n", values)
	if len(values) == 0 {
		return
	}
	if pick == "first" {
		fmt.Fprintf(w, "picked=%q\n", values[0])
	} else {
		fmt.Fprintf(w, "picked=%q\n", values[len(values)-1])
	}
}

// /filter?q=... demonstrates loose regex blocking with decoding confusion
func filterHandler(w http.ResponseWriter, r *http.Request) {
	q := getRawParam(r, "q")
	// Loose, easily bypassed filter
	// But process a double-decoded variant (auto-decoding behavior)
	d1, _ := url.QueryUnescape(q)
	d2, _ := url.QueryUnescape(d1)
	fmt.Fprintf(w, "%s", d2)
}

// /xss?q=... naive block of literal "<script" only; allows entities like &#x73;cript to pass
func xssHandler(w http.ResponseWriter, r *http.Request) {
	q := getRawParam(r, "q")
	// Decode HTML entities to simulate browser interpretation
	decoded := html.UnescapeString(q)
	// Reflect unsafely as HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "%s", decoded)
}

// /headers shows header parsing ambiguities
func headersHandler(w http.ResponseWriter, r *http.Request) {
	// Show first vs last semantics for duplicate headers
	pick := strings.ToLower(r.URL.Query().Get("pick")) // first|last
	key := r.URL.Query().Get("key")
	if key == "" {
		key = "X-Demo"
	}
	values := r.Header.Values(key)
	fmt.Fprintf(w, "all=%q\n", values)
	if len(values) == 0 {
		return
	}
	switch pick {
	case "first":
		fmt.Fprintf(w, "picked=%q\n", values[0])
	default:
		fmt.Fprintf(w, "picked=%q\n", values[len(values)-1])
	}
}

// /nullbyte?name=...
func nullByteHandler(w http.ResponseWriter, r *http.Request) {
	name := getRawParam(r, "name")
	// Log up to null, process after null (mismatch)
	parts := strings.SplitN(name, "\x00", 2)
	logName := parts[0]
	processName := name
	if len(parts) == 2 {
		processName = parts[1]
	}
	log.Printf("user=%q", logName)
	fmt.Fprintf(w, "hello %s", processName)
}

// /hpp?a=1&a=2 demonstrates HTTP parameter pollution
func hppHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key := r.URL.Query().Get("key")
	if key == "" {
		key = "a"
	}
	fmt.Fprintf(w, "first=%q last=%q all=%q\n", q.Get(key), last(q[key]), q[key])
}

// /semicolon?raw=a=1;b=2&also=c — treat semicolons as separators (quirky behavior)
func semicolonHandler(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("raw")
	if raw == "" {
		raw = r.URL.RawQuery
	}
	// Split on both & and ;
	pairs := strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' })
	vals := url.Values{}
	for _, p := range pairs {
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		k := kv[0]
		v := ""
		if len(kv) == 2 {
			v = kv[1]
		}
		vals.Add(k, v)
	}
	fmt.Fprintf(w, "parsed=%q\n", vals.Encode())
}

// /methods supports odd methods and overrides
func methodsHandler(w http.ResponseWriter, r *http.Request) {
	override := r.Header.Get("X-HTTP-Method-Override")
	method := r.Method
	if override != "" {
		method = override
	}
	// Allow TRACE-like echo
	if strings.EqualFold(method, "TRACE") {
		// Dangerous: reflect headers
		var b strings.Builder
		for k, vs := range r.Header {
			fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(vs, ", "))
		}
		w.Header().Set("Content-Type", "message/http")
		fmt.Fprint(w, b.String())
		return
	}
	fmt.Fprintf(w, "method=%s override=%s\n", r.Method, override)
}

// /chain?value=...&steps=url,b64,hex applies chained decodes
func chainHandler(w http.ResponseWriter, r *http.Request) {
	value := getRawParam(r, "value")
	steps := strings.Split(r.URL.Query().Get("steps"), ",")
	for _, s := range steps {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		v, err := decodeOnce(s, value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		value = v
	}
	fmt.Fprint(w, value)
}

// /proxy trusts reverse proxy headers
func proxyTrustHandler(w http.ResponseWriter, r *http.Request) {
	xff := r.Header.Get("X-Forwarded-For")
	originalURL := r.Header.Get("X-Original-URL")
	clientIP := strings.TrimSpace(strings.Split(xff, ",")[0])
	admin := clientIP == "127.0.0.1" || clientIP == "::1"
	fmt.Fprintf(w, "xff=%q ip=%q admin=%v original_url=%q\n", xff, clientIP, admin, originalURL)
	if admin {
		fmt.Fprintln(w, "welcome admin")
	}
}

// /desync attempts to echo raw request in a naive way using Hijacker
// This is only for demonstration and can behave unexpectedly behind certain proxies.
func desyncEchoHandler(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	// Intentionally read a fixed number of bytes, potentially leaving extra bytes in the buffer
	bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
	bufrw.WriteString("Raw request (first 1024 bytes):\n")
	// Write already buffered request data
	if bufrw.Reader != nil {
		// Peek without consuming too much
		data, _ := bufrw.Reader.Peek(1024)
		bufrw.Write(data)
	}
	bufrw.Flush()
}

// /case?Param=... demonstrates case sensitivity confusion in query keys
func caseSensitivityHandler(w http.ResponseWriter, r *http.Request) {
	// Treat parameters with exact case differently
	upper := r.URL.Query().Get("Param")
	lower := r.URL.Query().Get("param")
	mixed := r.URL.Query().Get("pArAm")
	fmt.Fprintf(w, "Param=%q param=%q pArAm=%q\n", upper, lower, mixed)
	// But when processing, collapse to lower
	combined := r.URL.Query()
	collapsed := url.Values{}
	for k, vs := range combined {
		collapsed[strings.ToLower(k)] = vs
	}
	fmt.Fprintf(w, "collapsed=%q\n", collapsed.Encode())
}

// /upload — unsafe file upload saving using provided filename
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/") {
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			if part.FileName() == "" {
				continue
			}
			// Dangerous conversion enabling backslash traversal
			unsafeName := part.FileName()
			unsafeName = strings.ReplaceAll(unsafeName, "\\", string(os.PathSeparator))
			data, _ := io.ReadAll(part)
			destDir := filepath.Join(os.TempDir(), "uploads")
			_ = os.MkdirAll(destDir, 0o777)
			dest := filepath.Join(destDir, unsafeName)
			_ = os.MkdirAll(filepath.Dir(dest), 0o777)
			_ = os.WriteFile(dest, data, 0o666)
			fmt.Fprintf(w, "saved=%q size=%d\n", dest, len(data))
		}
		return
	}
	http.Error(w, "multipart/form-data required", http.StatusUnsupportedMediaType)
}

// /xml — naive entity expansion that fetches external SYSTEM identifiers
func xmlHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s := string(body)
	// Find a simple external entity: <!ENTITY name SYSTEM "target">
	re := regexp.MustCompile(`<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>`)
	m := re.FindStringSubmatch(s)
	if len(m) == 3 {
		name := m[1]
		target := m[2]
		var fetched []byte
		if strings.HasPrefix(target, "file://") {
			p := strings.TrimPrefix(target, "file://")
			fetched, _ = os.ReadFile(p)
		} else if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			resp, err := http.Get(target)
			if err == nil {
				defer resp.Body.Close()
				fetched, _ = io.ReadAll(resp.Body)
			}
		}
		s = strings.ReplaceAll(s, "&"+name+";", string(fetched))
	}
	// Reflect possibly dangerous processed body
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, s)
}

// Helpers

func getRawParam(r *http.Request, key string) string {
	// Ambiguity: prefer last value, not first
	vs := r.URL.Query()[key]
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1]
}

func last(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1]
}

func decodeOnce(mode, s string) (string, error) {
	switch mode {
	case "url":
		return url.QueryUnescape(s)
	case "b64", "base64":
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			// Try URL encoding variant
			d2, err2 := base64.URLEncoding.DecodeString(s)
			if err2 != nil {
				return "", err
			}
			return string(d2), nil
		}
		return string(data), nil
	case "hex":
		data, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			return "", err
		}
		return string(data), nil
	case "html":
		return html.UnescapeString(s), nil
	case "octal":
		return decodeOctalEscapes(s), nil
	case "unicode":
		return decodeUnicodeEscapes(s), nil
	case "ws", "whitespace":
		return removeOddWhitespace(s), nil
	case "idna":
		// Very naive: split host and attempt puny-like lowercasing only
		parts := strings.Split(s, "/")
		if len(parts) > 0 {
			parts[0] = strings.ToLower(parts[0])
		}
		return strings.Join(parts, "/"), nil
	default:
		return s, nil
	}
}

func removeOddWhitespace(s string) string {
	// Remove a set of uncommon whitespace characters
	odd := []rune{'\u00A0', '\u2007', '\u202F', '\u200B', '\u200C', '\u200D', '\u2060'}
	for _, r := range odd {
		s = strings.ReplaceAll(s, string(r), "")
	}
	return s
}

func decodeOctalEscapes(s string) string {
	var out bytes.Buffer
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
				val := (int(s[i+1]-'0') << 6) | (int(s[i+2]-'0') << 3) | int(s[i+3]-'0')
				out.WriteByte(byte(val))
				i += 3
				continue
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

func isOctal(b byte) bool { return b >= '0' && b <= '7' }

func decodeUnicodeEscapes(s string) string {
	// Handle \uXXXX and \xHH sequences
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'u':
				if i+6 <= len(s) {
					hexDigits := s[i+2 : i+6]
					if v, err := strconv.ParseInt(hexDigits, 16, 32); err == nil {
						out.WriteRune(rune(v))
						i += 5
						continue
					}
				}
			case 'x':
				if i+4 <= len(s) {
					hexDigits := s[i+2 : i+4]
					if v, err := strconv.ParseInt(hexDigits, 16, 8); err == nil {
						out.WriteByte(byte(v))
						i += 3
						continue
					}
				}
			}
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

// splitLoose splits naive JSON-like text into tokens by punctuation
func splitLoose(s string) []string {
	seps := func(r rune) bool {
		switch r {
		case '{', '}', ':', ',', '\n', '\r', '\t', ' ', '"', '\'':
			return true
		}
		return false
	}
	fields := strings.FieldsFunc(s, seps)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func applyCase(mode, s string) string {
	switch strings.ToLower(mode) {
	case "upper":
		return strings.ToUpper(s)
	case "lower":
		return strings.ToLower(s)
	default:
		return s
	}
}

// Utilities to create a fake multipart body in tests (not used by handlers directly)
func buildMultipart(fieldName, filename string, data []byte) (string, *bytes.Buffer) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {fmt.Sprintf("form-data; name=\"%s\"; filename=\"%s\"", fieldName, filename)},
		"Content-Type":        {"application/octet-stream"},
	})
	_, _ = part.Write(data)
	writer.Close()
	return writer.FormDataContentType(), body
}

// unused references to avoid import removal when building variations in the future
var _ = net.IPv4len
