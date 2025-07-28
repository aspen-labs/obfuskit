package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"obfuskit/internal/constants"
	"strings"
	"testing"
)

func startServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/burp", processBurpRequestHandler) // update as needed
	return httptest.NewServer(mux)
}

func TestBurpIntegration(t *testing.T) {
	// start the server
	srv := startServer()
	defer srv.Close()

	// send a request
	resp, err := http.Post(srv.URL+"/burp", "application/json", strings.NewReader(`{"payload":"abc"}`))
	if err != nil {
		t.Fatalf("failed to post request: %v", err)
	}
	defer resp.Body.Close()

	// verify the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	var result BurpResponse
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
