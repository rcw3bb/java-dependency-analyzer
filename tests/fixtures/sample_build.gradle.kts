// Kotlin DSL build.gradle.kts test fixture
plugins {
    kotlin("jvm") version "1.9.0"
}

val resolvedVersion = "3.9.1"

dependencies {
    // Kotlin shorthand notation
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")
    api("com.google.guava:guava:31.0-jre")
    runtimeOnly("org.postgresql:postgresql:42.3.1")

    // Block notation
    implementation(group = "org.springframework", name = "spring-core", version = "5.3.20")

    // Test dependency - should be excluded
    testImplementation("junit:junit:4.13.2")

    // Duplicate - should appear once
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")

    // Resolved val variable - should be included
    implementation("org.yaml:snakeyaml:${resolvedVersion}")
}
