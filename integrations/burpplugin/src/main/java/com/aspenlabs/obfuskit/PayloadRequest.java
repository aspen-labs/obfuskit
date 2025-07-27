package com.aspenlabs.obfuskit;

// PayloadRequest class for structured JSON
public class PayloadRequest {
  private final String payload;

  public PayloadRequest(String payload) {
    this.payload = payload;
  }

  public String getPayload() {
    return payload;
  }
}
