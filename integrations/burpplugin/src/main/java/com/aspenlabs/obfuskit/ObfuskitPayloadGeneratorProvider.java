package com.aspenlabs.obfuskit;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.PayloadGenerator;
import burp.api.montoya.intruder.PayloadGeneratorProvider;

public class ObfuskitPayloadGeneratorProvider implements PayloadGeneratorProvider {
  private final MontoyaApi api;

  public ObfuskitPayloadGeneratorProvider(MontoyaApi api) {
    this.api = api;
  }

  @Override
  public String displayName() {
    api.logging().logToOutput("Obfuskit Evasion Payloads provider");
    return "Obfuskit Evasion Payloads";
  }

  @Override
  public PayloadGenerator providePayloadGenerator(AttackConfiguration attackConfiguration) {
    api.logging()
        .logToOutput(
            "Obfuskit Evasion Payloads provider attackConfiguration: "
                + attackConfiguration.toString());
    return new ObfuskitPayloadGenerator(api);
  }
}
