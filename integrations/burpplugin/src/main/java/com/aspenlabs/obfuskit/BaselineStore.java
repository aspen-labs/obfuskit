package com.aspenlabs.obfuskit;

public class BaselineStore {
  private static volatile String lastRequestRaw = "";
  private static volatile String lastResponseRaw = "";

  public static void setLastRequestRaw(String body) {
    if (body != null) {
      lastRequestRaw = body;
    }
  }

  public static void setLastResponseRaw(String body) {
    if (body != null) {
      lastResponseRaw = body;
    }
  }

  public static String getLastRequestRaw() {
    return lastRequestRaw;
  }

  public static String getLastResponseRaw() {
    return lastResponseRaw;
  }
}
