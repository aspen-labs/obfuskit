package com.aspenlabs.obfuskit;

// Model for each payload object
public class Payload {
  private final String originalPayload;
  private final String attackType;
  private final String evasionType;
  private final String level;
  private final String variant;

  public Payload(
      String originalPayload, String attackType, String evasionType, String level, String variant) {
    this.originalPayload = originalPayload;
    this.attackType = attackType;
    this.evasionType = evasionType;
    this.level = level;
    this.variant = variant;
  }

  public String getOriginalPayload() {
    return originalPayload;
  }

  public String getAttackType() {
    return attackType;
  }

  public String getEvasionType() {
    return evasionType;
  }

  public String getLevel() {
    return level;
  }

  public String getVariant() {
    return variant;
  }

  public String toString() {
    return String.format(
        "Original Payload: %s, Attack Type: %s, Evasion Type: %s, Level: %s, Variant: %s",
        originalPayload, attackType, evasionType, level, variant);
  }
}
