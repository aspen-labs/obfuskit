package com.aspenlabs.obfuskit;

import static org.junit.jupiter.api.Assertions.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.intruder.GeneratedPayload;
import burp.api.montoya.intruder.IntruderInsertionPoint;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class ObfuskitPayloadGeneratorTest {
  static com.sun.net.httpserver.HttpServer server;

  @BeforeAll
  static void setUp() throws Exception {
    // Start a simple HTTP server to mock the API endpoint
    server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(8080), 0);
    server.createContext(
        "/api/payloads",
        exchange -> {
          String response =
              "{\"status\":\"ok\",\"payloads\":[{\"original_payload\":\"abc\",\"attack_type\":\"generic\",\"evasion_type\":\"Base64Variants\",\"level\":2,\"variant\":\"v1\"}]}";
          exchange.sendResponseHeaders(200, response.length());
          OutputStream os = exchange.getResponseBody();
          os.write(response.getBytes());
          os.close();
        });
    server.start();
  }

  @AfterAll
  static void tearDown() {
    server.stop(0);
  }

  @Test
  void testGeneratePayloadFor() {
    MontoyaApi api = Mockito.mock(MontoyaApi.class);
    ObfuskitPayloadGenerator generator = new ObfuskitPayloadGenerator(api);
    IntruderInsertionPoint insertionPoint = Mockito.mock(IntruderInsertionPoint.class);
    Mockito.when(insertionPoint.baseValue()).thenAnswer(invocation -> "abc");

    GeneratedPayload genPayload = generator.generatePayloadFor(insertionPoint);
    assertNotNull(genPayload);
    assertEquals("abc", genPayload.toString());
    genPayload = generator.generatePayloadFor(insertionPoint);
    assertNotEquals("abc", genPayload.toString());
  }
}
