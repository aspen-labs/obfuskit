package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndex(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	withLogging(indexHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "obfuskitvulnapp") {
		t.Fatalf("unexpected: code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestEcho_DoubleURL_DangerousReflect(t *testing.T) {
	rr := httptest.NewRecorder()
	// q is double URL encoded <script>alert(1)</script>
	req := httptest.NewRequest(http.MethodGet, "/echo?q=%253Cscript%253Ealert(1)%253C%2Fscript%253E&enc=url,url&mode=raw", nil)
	withLogging(echoHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "<script>alert(1)</script>") {
		t.Fatalf("expected reflected script; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestDecode_Base64(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/decode?mode=b64&value=aGVsbG8=&repeat=1", nil)
	withLogging(decodeHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || rr.Body.String() != "hello" {
		t.Fatalf("expected hello; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestNormalize(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/normalize?u=..%2Ffiles%2Fsample.txt", nil)
	withLogging(normalizeHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "raw=") {
		t.Fatalf("unexpected normalize output: %d %q", rr.Code, rr.Body.String())
	}
}

func TestPath_ReadSample(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/path?file=sample.txt", nil)
	withLogging(pathHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "harmless sample file") {
		t.Fatalf("expected sample content; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestPathWindows_ReadSample(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/pathwin?file=sample.txt", nil)
	withLogging(pathWindowsHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "harmless sample file") {
		t.Fatalf("expected sample content; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestJSON_MisparseAndHPP(t *testing.T) {
	rr := httptest.NewRecorder()
	body := strings.NewReader("a=1&b=2&a=3")
	req := httptest.NewRequest(http.MethodPost, "/json?a=9", body)
	req.Header.Set("Content-Type", "text/plain")
	withLogging(jsonHandler).ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	// Last writer wins for 'a' from URL
	got := rr.Body.String()
	if !strings.Contains(got, "\"a\":\"9\"") || !strings.Contains(got, "\"b\":\"2\"") {
		t.Fatalf("unexpected json body: %q", got)
	}
}

func TestMimeSniff_HTMLReflect(t *testing.T) {
	rr := httptest.NewRecorder()
	htmlDoc := "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head><body>Hi</body></html>"
	req := httptest.NewRequest(http.MethodPost, "/mime", strings.NewReader(htmlDoc))
	req.Header.Set("Content-Type", "application/octet-stream")
	withLogging(mimeSniffHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Header().Get("Content-Type"), "text/html") || !strings.Contains(rr.Body.String(), "<html>") {
		t.Fatalf("expected sniffed html reflect; got code=%d ct=%q body=%q", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
}

func TestFilter_LooseBypass(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/filter?q=%253Cscript%253Ealert(1)%253C%2Fscript%253E", nil)
	withLogging(filterHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "<script>") {
		t.Fatalf("expected bypass and decode; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestXSS_EntityBypass(t *testing.T) {
	rr := httptest.NewRecorder()
	// Replace <script> with &#x73;cript to bypass literal filter
	payload := urlQuery(`<!DOCTYPE html><body><scr&#x69;pt>window.__x=1</scr&#x69;pt></body>`) // also hex-entity inside tag name
	req := httptest.NewRequest(http.MethodGet, "/xss?q="+payload, nil)
	withLogging(xssHandler).ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<script>") && !strings.Contains(strings.ToLower(body), "<script") && !strings.Contains(body, "window.__x=1") {
		t.Fatalf("expected decoded/bypassed script; got %q", body)
	}
}

// urlQuery percent-encodes a string minimalistically for query usage
func urlQuery(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		// Encode reserved and non-alnum
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func TestHeaders_AmbiguityPickLast(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/headers?pick=last&key=X-Test", nil)
	req.Header.Add("X-Test", "one")
	req.Header.Add("X-Test", "two")
	withLogging(headersHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "picked=\"two\"") {
		t.Fatalf("expected pick last; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestCookies_Ambiguity(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cookies?name=SESSION&pick=last", nil)
	req.AddCookie(&http.Cookie{Name: "SESSION", Value: "a"})
	req.AddCookie(&http.Cookie{Name: "SESSION", Value: "b"})
	withLogging(cookiesHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "picked=\"b\"") {
		t.Fatalf("expected cookie last; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestNullByte_Mismatch(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nullbyte?name=admin%00root", nil)
	withLogging(nullByteHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "hello root") {
		t.Fatalf("expected hello root; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestHPP(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/hpp?a=1&a=2&a=3", nil)
	withLogging(hppHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "first=\"1\" last=\"3\"") {
		t.Fatalf("unexpected hpp body: %q", rr.Body.String())
	}
}

func TestSemicolonParsing(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/semicolon?raw=a=1;b=2&also=c", nil)
	withLogging(semicolonHandler).ServeHTTP(rr, req)
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "raw=a%3D1") || !strings.Contains(body, "b=2") || !strings.Contains(body, "also=c") {
		t.Fatalf("unexpected semicolon parse: %q", body)
	}
}

func TestMethods_OverrideTRACE(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/methods", nil)
	req.Header.Set("X-HTTP-Method-Override", "TRACE")
	req.Header.Set("X-Demo", "value")
	withLogging(methodsHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || rr.Header().Get("Content-Type") != "message/http" || !strings.Contains(rr.Body.String(), "X-Demo: value") {
		t.Fatalf("expected TRACE echo; code=%d ct=%q body=%q", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
	}
}

func TestChain_URLThenBase64(t *testing.T) {
	// value is URL-encoded base64 of "test" -> dGVzdA== -> dGVzdA%3D%3D
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/chain?value=dGVzdA%3D%3D&steps=url,b64", nil)
	withLogging(chainHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || rr.Body.String() != "test" {
		t.Fatalf("expected test; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestProxy_TrustXFF(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
	req.Header.Set("X-Forwarded-For", "127.0.0.1, 1.2.3.4")
	withLogging(proxyTrustHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "welcome admin") {
		t.Fatalf("expected admin; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestCaseSensitivity(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/case?Param=AAA&param=bbb&pArAm=ccc", nil)
	withLogging(caseSensitivityHandler).ServeHTTP(rr, req)
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "Param=\"AAA\" param=\"bbb\" pArAm=\"ccc\"") {
		t.Fatalf("unexpected case output: %q", body)
	}
}

func TestUpload_UnsafeFilename(t *testing.T) {
	rr := httptest.NewRecorder()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("file", "nested/evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(fw, "content")
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	withLogging(uploadHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "saved=") {
		t.Fatalf("unexpected upload resp: %d %q", rr.Code, rr.Body.String())
	}
}

func TestXML_ExternalEntity_File(t *testing.T) {
	// Create temp file and reference via file://
	dir := t.TempDir()
	p := filepath.Join(dir, "xxe.txt")
	content := "SECRET-XXE"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	xmlBody := fmt.Sprintf("<!DOCTYPE x [<!ENTITY e SYSTEM \"file://%s\">]><x>&e;</x>", p)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/xml", strings.NewReader(xmlBody))
	withLogging(xmlHandler).ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), content) {
		t.Fatalf("expected expanded entity; got %d %q", rr.Code, rr.Body.String())
	}
}

func TestHeaders_Desync_NotSupportedWithRecorder(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/desync", nil)
	withLogging(desyncEchoHandler).ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "hijacking not supported") {
		t.Fatalf("expected 500 for hijacking unsupported; got %d %q", rr.Code, rr.Body.String())
	}
}
