package com.aspenlabs.obfuskit;

// Structured parser for the response
public class PayloadResponse {
  private final java.util.List<Payload> payloads;

  public PayloadResponse(java.util.List<Payload> payloads) {
    this.payloads = payloads;
  }

  public java.util.List<Payload> getPayloads() {
    return payloads;
  }

  // Parse from JSON string
  public static PayloadResponse fromJson(String json) {
    java.util.List<Payload> payloads = new java.util.ArrayList<>();
    org.json.JSONObject obj = new org.json.JSONObject(json);
    if (obj.has("payloads")) {
      org.json.JSONArray arr = obj.getJSONArray("payloads");
      for (int i = 0; i < arr.length(); i++) {
        org.json.JSONObject payloadObj = arr.getJSONObject(i);
        Payload p =
            new Payload(
                payloadObj.optString("original_payload", null),
                payloadObj.optString("attack_type", null),
                payloadObj.optString("evasion_type", null),
                payloadObj.optString("level", null),
                payloadObj.optString("variant", null));
        payloads.add(p);
      }
    }
    return new PayloadResponse(payloads);
  }
}
