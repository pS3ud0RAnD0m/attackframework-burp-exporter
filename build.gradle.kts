plugins {
    id("java")
}

group = project.property("group").toString()
version = project.property("version").toString()

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.6")

    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.mockito:mockito-core:5.12.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.12.0")
    testImplementation("org.assertj:assertj-core:3.26.3")

    // JUnit engine + launcher to be explicit/future-proof
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // Show useful client logs during tests
    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.13")

    implementation("com.fasterxml.jackson.core:jackson-core:2.15.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
    implementation("com.miglayout:miglayout-swing:11.0")
    implementation("jakarta.json:jakarta.json-api:2.1.1")
    implementation("org.glassfish:jakarta.json:2.0.1")
    implementation("org.opensearch.client:opensearch-java:3.1.0")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("java.awt.headless", "true")

    // Log output from tests and client
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }

    // slf4j-simple configuration (adjust as needed: trace|debug|info|warn|error)
    systemProperty("org.slf4j.simpleLogger.defaultLogLevel", "info")
    // Example: quiet down verbose categories
    // systemProperty("org.slf4j.simpleLogger.log.org.apache.hc.client5", "warn")
    // systemProperty("org.slf4j.simpleLogger.log.org.opensearch.client", "info")
}

tasks.register<Jar>("fatJar") {
    archiveBaseName.set(project.property("archivesBaseName").toString())
    archiveVersion.set(project.property("version").toString())

    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith("jar") }
            .map { zipTree(it) }
    })
}

tasks.named<Jar>("jar") {
    enabled = false
}

tasks.assemble {
    dependsOn("fatJar")
}
tasks.build {
    dependsOn("fatJar")
}
