package com.aspenlabs.obfuskit;

import static burp.api.montoya.intruder.PayloadProcessingResult.usePayload;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.URLUtils;

public class ObfuskitPayloadProcessor implements PayloadProcessor {

  public static final String INPUT_PREFIX = "input=";
  private final MontoyaApi api;

  public ObfuskitPayloadProcessor(MontoyaApi api) {
    this.api = api;
  }

  @Override
  public String displayName() {
    return "Obfuskit Evasion Plugin";
  }

  @Override
  public PayloadProcessingResult processPayload(PayloadData payloadData) {
    api.logging().logToOutput("Processing payload: " + payloadData.currentPayload());

    Base64Utils base64Utils = api.utilities().base64Utils();
    URLUtils urlUtils = api.utilities().urlUtils();

    // Decode the base value
    String dataParameter =
        base64Utils.decode(urlUtils.decode(payloadData.insertionPoint().baseValue())).toString();

    // Parse the location of the input string in the decoded data
    String prefix = findPrefix(dataParameter);
    if (prefix == null) {
      return usePayload(payloadData.currentPayload());
    }

    String suffix = findSuffix(dataParameter);
    // Rebuild serialized data with the new payload
    String rebuiltDataParameter = prefix + payloadData.currentPayload() + suffix;
    ByteArray reserializedDataParameter = urlUtils.encode(base64Utils.encode(rebuiltDataParameter));

    return usePayload(reserializedDataParameter);
  }

  private String findPrefix(String dataParameter) {
    api.logging().logToOutput("Finding prefix: " + dataParameter);
    int start = dataParameter.indexOf(INPUT_PREFIX);
    if (start == -1) {
      return null;
    }
    start += INPUT_PREFIX.length();
    return dataParameter.substring(0, start);
  }

  private String findSuffix(String dataParameter) {
    api.logging().logToOutput("Finding suffix: " + dataParameter);
    int start = dataParameter.indexOf(INPUT_PREFIX);
    int end = dataParameter.indexOf("&", start);
    if (end == -1) {
      end = dataParameter.length();
    }
    api.logging().logToOutput("Found suffix: " + dataParameter.substring(end));
    return dataParameter.substring(end);
  }
}
