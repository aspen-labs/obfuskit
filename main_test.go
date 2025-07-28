package main

import (
	"encoding/json"
	"go/types"
	"io"
	"net/http"
	"net/http/httptest"
	"obfuskit/constants"
	"obfuskit/internal/model"
	"obfuskit/internal/server"
	"strings"
	"testing"
)

func mockProcessServerRequestHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","payloads":[
		{
			"originalPayload":"a+b",
			"attackType":"generic",
			"evasionType":"Base64Variants",
			"level":"Medium",
			"variant":"YWI="
		},
		{
			"originalPayload":"abc",
			"attackType":"generic",
			"evasionType":"URLVariants",
			"level":"Medium",
			"variant":"%61%62%63"
		}
	]}`))
}

func startServer() *httptest.Server {
	exampleConfig := &types.Config{
		Action: "Send to URL",
		Attack: struct {
			Type string `yaml:"type" json:"type"`
		}{
			Type: "xss",
		},
		Payload: struct {
			Method   string   `yaml:"method" json:"method"`
			Encoding string   `yaml:"encoding" json:"encoding"`
			Source   string   `yaml:"source" json:"source"`
			FilePath string   `yaml:"file_path" json:"file_path"`
			Custom   []string `yaml:"custom" json:"custom"`
		}{
			Method: "Auto",
			Source: "Auto",
		},
		Evasion: struct {
			Level string `yaml:"level" json:"level"`
		}{
			Level: "Medium",
		},
		Target: struct {
			Method string `yaml:"method" json:"method"`
			URL    string `yaml:"url" json:"url"`
		}{
			Method: "URL",
			URL:    "http://example.com/vulnerable-page",
		},
		Report: struct {
			Type string `yaml:"type" json:"type"`
			Auto bool   `yaml:"auto" json:"auto"`
		}{
			Type: "HTML",
			Auto: true,
		},
	}
	mux := http.NewServeMux()
	handler := &server.ServerHandler{Config: exampleConfig}
	mux.Handle("/api/payloads", handler)
	return httptest.NewServer(mux)
}

func TestBurpIntegration(t *testing.T) {
	// start the server
	srv := startServer()
	defer srv.Close()

	// send a request
	resp, err := http.Post(srv.URL+"/api/payload", "application/json", strings.NewReader(`{"payload":"abc"}`))
	if err != nil {
		t.Fatalf("failed to post request: %v", err)
	}
	defer resp.Body.Close()

	// verify the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	var result model.PayloadResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if result.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q", result.Status)
	}
	if len(result.Payloads) != 21 {
		t.Fatalf("expected 21 payloads, got %d", len(result.Payloads))
	}
	payload := result.Payloads[0]
	if payload.OriginalPayload != "abc" {
		t.Fatalf("expected original payload 'abc', got %q", payload.OriginalPayload)
	}
	if payload.AttackType != "generic" {
		t.Fatalf("expected attack type 'generic', got %q", payload.AttackType)
	}
	if payload.EvasionType != "Base64Variants" {
		t.Fatalf("expected evasion type 'Base64Variants', got %q", payload.EvasionType)
	}
	if payload.Level != constants.Medium {
		t.Fatalf("expected evasion level 'Medium', got %q", payload.Level)
	}
	if payload.Variant == "" {
		t.Fatalf("expected variant, got empty string")
	}
}
