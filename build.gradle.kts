plugins {
    id("java")
    id("jacoco")
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

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    testRuntimeOnly("org.slf4j:slf4j-simple:2.0.13")

    implementation("com.fasterxml.jackson.core:jackson-core:2.15.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
    implementation("com.miglayout:miglayout-swing:11.0")
    implementation("jakarta.json:jakarta.json-api:2.1.1")
    implementation("org.glassfish:jakarta.json:2.0.1")
    implementation("org.opensearch.client:opensearch-java:3.1.0")
}

tasks.test {
    useJUnitPlatform {
        if (project.hasProperty("excludeIntegration")) {
            excludeTags("integration")
        }
    }

    systemProperty("java.awt.headless", "true")

    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }

    systemProperty("org.slf4j.simpleLogger.defaultLogLevel", "info")
}

tasks.named<JacocoReport>("jacocoTestReport") {
    dependsOn(tasks.test)
    reports {
        xml.required.set(false)
        csv.required.set(false)
        html.required.set(true)
    }
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
