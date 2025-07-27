package com.aspenlabs.obfuskit;

import static org.mockito.Mockito.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.intruder.Intruder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ObfuskitExtensionTest {

  private MontoyaApi api;
  private Extension extension;
  private Intruder intruder;

  @BeforeEach
  void setUp() {
    api = mock(MontoyaApi.class);
    extension = mock(Extension.class);
    intruder = mock(Intruder.class);

    when(api.extension()).thenReturn(extension);
    when(api.intruder()).thenReturn(intruder);
  }

  @Test
  void testInitialize() {
    ObfuskitExtension obfuskitExtension = new ObfuskitExtension();
    obfuskitExtension.initialize(api);

    verify(extension).setName("Obfuskit Evasion Plugin");
    verify(intruder).registerPayloadGeneratorProvider(any(ObfuskitPayloadGeneratorProvider.class));
    verify(intruder).registerPayloadProcessor(any(ObfuskitPayloadProcessor.class));
  }
}
