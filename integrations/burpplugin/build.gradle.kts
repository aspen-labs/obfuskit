plugins {
    id("java-library")
    id("com.diffplug.spotless") version "6.25.0"
}

repositories {
    mavenCentral()
}


sourceSets {
    main {
        java {
            srcDirs("src/main/java")
        }
    }
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("org.mockito:mockito-core:5.2.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.2.0")
    implementation("net.portswigger.burp.extensions:montoya-api:2025.5")
    testImplementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.10")
    implementation("org.json:json:20250517")
}

tasks.withType<JavaCompile> {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

spotless {
    java {
        googleJavaFormat()
        target("src/main/java/**/*.java", "src/test/java/**/*.java")
    }
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}