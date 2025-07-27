# Obfuskit Burp Integration Plugins

# Obfuskit Burp Integration Plugins

This directory contains plugins for integrating Burp Suite with Obfuskit for payload evasion. The primary focus is now on the modern Java plugin using the official Burp Montoya API and Gradle build system.

## Features
- Send payloads or requests from Burp to Obfuskit for evasion.
- View all evaded payloads and their details directly in Burp.
- Modern Java plugin using Burp Montoya API (2025.x).
- Automated code formatting with Spotless and Google Java Format.

---

## Requirements
- Burp Suite (Community or Professional)
- Java 21+
- Obfuskit running with the `-server` flag (listening on http://localhost:8181/api/payloads)
- [Montoya API](https://portswigger.net/burp/extender/api) dependency is managed via Gradle

## Java Plugin

### Build & Format Instructions

1. Clone this repository and navigate to `integrations/burpplugin`.
2. Build the plugin JAR:
   ```sh
   ./gradlew build
   ```

3. The built JAR will be in `build/libs/`.
4. Load the JAR into Burp Suite via Extender > Extensions > Add > Extension type: Java.

### Configuration
- Ensure Obfuskit is running with a valid config file and the `-server` flag:
  ```sh
  go run ./... -server -config ./config_server.yaml
  ```
- The Java plugin expects the Obfuskit server endpoint at `http://localhost:8181/api/payloads`.
- See `config_server.yaml` for example configuration.

### Development Notes
- Uses Gradle Kotlin DSL (`build.gradle.kts`).
- Uses Spotless for code formatting (Google Java Format).
- Dependencies (including Montoya API and org.json) are managed via Gradle.

### Testing
- Unit tests use JUnit 5 and Mockito.
- Run tests with:
  ```sh
  ./gradlew test
  ```

---

## Legacy Plugins
- Python (Jython) and Maven-based Java plugins are deprecated and not maintained.
- Use the Java Montoya API plugin for best results and compatibility with modern Burp Suite versions.

### Installation in Burp

1. In Burp, go to **Extender → Extensions → Add**.
2. Set **Extension type** to `Java`.
3. Select the generated JAR file.
4. Ensure Obfuskit is running: `obfuskit --server -config ./config_server.yaml`

**Usage:**
- Right-click a request and send to Intruder.
- Select the payload position.
- In the Intruder tab, go to **Positions** and select **Add**.
- In the Payload Type dropdown, select **Extension-Generated**.
- Select the Java plugin "Obfuskit Evasion Plugin" from the list.
- Start the attack.

---

## Troubleshooting
- Make sure Obfuskit is running and accessible at `http://localhost:8080/burp`.
- For Java plugin, ensure Burp Extender API and org.json dependencies are available (see pom.xml).

---

## License
See the root Obfuskit repository for license details.