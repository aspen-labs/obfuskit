package com.aspenlabs.obfuskit;

// PayloadRequest class for structured JSON
public class PayloadRequest {
  private final String payload;
  private final String request_payload;
  private final String response_payload;

  public PayloadRequest(String payload, String requestPayload, String responsePayload) {
    this.payload = payload;
    this.request_payload = requestPayload;
    this.response_payload = responsePayload;
  }

  public String getPayload() {
    return payload;
  }

  public String getRequest_payload() {
    return request_payload;
  }

  public String getResponse_payload() {
    return response_payload;
  }
}
