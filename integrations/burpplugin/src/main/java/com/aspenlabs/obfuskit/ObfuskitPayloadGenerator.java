package com.aspenlabs.obfuskit;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.intruder.GeneratedPayload;
import burp.api.montoya.intruder.IntruderInsertionPoint;
import burp.api.montoya.intruder.PayloadGenerator;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class ObfuskitPayloadGenerator implements PayloadGenerator {
  private final MontoyaApi api;
  private final String endpoint;
  private List<Payload> payloads;
  private boolean hasProcessed;
  private int payloadIndex;

  public ObfuskitPayloadGenerator(MontoyaApi api) {
    this.api = api;
    this.endpoint = "http://localhost:8181/api/payloads";
    this.payloads = new ArrayList<>();
    this.hasProcessed = false;
    this.payloadIndex = 0;
  }

  @Override
  public GeneratedPayload generatePayloadFor(IntruderInsertionPoint insertionPoint) {
    api.logging().logToOutput("Generating payload for: " + insertionPoint.baseValue());
    if (!hasProcessed) {
      try {
        api.logging().logToOutput("Endpoint: " + endpoint);
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

        PayloadRequest payloadRequest = new PayloadRequest(insertionPoint.baseValue().toString());
        org.json.JSONObject jsonObj = new org.json.JSONObject(payloadRequest);
        String jsonBody = jsonObj.toString();

        HttpRequest request =
            HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(3))
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
          String responseBody = response.body();
          PayloadResponse parsed = PayloadResponse.fromJson(responseBody);
          payloads = parsed.getPayloads();
        }
      } catch (Exception e) {
        api.logging().logToError("Error: " + e.getMessage());
      }
      hasProcessed = true;
    }

    if (payloadIndex >= payloads.size()) {
      return GeneratedPayload.end();
    }
    Payload payload = payloads.get(payloadIndex);
    api.logging().logToOutput("Payload Object: " + payload);
    payloadIndex++;
    return GeneratedPayload.payload(payload.getVariant());
  }
}
