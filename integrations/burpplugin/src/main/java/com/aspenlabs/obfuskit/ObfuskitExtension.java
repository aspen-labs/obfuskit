package com.aspenlabs.obfuskit;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class ObfuskitExtension implements BurpExtension {

  @Override
  public void initialize(MontoyaApi api) {
    api.logging().logToOutput("Obfuskit Evasion Plugin initialized");
    api.extension().setName("Obfuskit Evasion Plugin");
    api.intruder().registerPayloadGeneratorProvider(new ObfuskitPayloadGeneratorProvider(api));
    api.intruder().registerPayloadProcessor(new ObfuskitPayloadProcessor(api));
  }
}
