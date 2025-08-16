import org.gradle.api.tasks.testing.TestDescriptor
import org.gradle.api.tasks.testing.TestListener
import org.gradle.api.tasks.testing.TestResult

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
    compileOnly("ch.qos.logback:logback-classic:1.5.18")

    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.mockito:mockito-core:5.12.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.12.0")
    testImplementation("org.assertj:assertj-core:3.26.3")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    runtimeOnly("ch.qos.logback:logback-classic:1.5.18")

    implementation("com.fasterxml.jackson.core:jackson-core:2.15.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
    implementation("com.miglayout:miglayout-swing:11.0")
    implementation("jakarta.json:jakarta.json-api:2.1.1")
    implementation("org.glassfish:jakarta.json:2.0.1")
    implementation("org.opensearch.client:opensearch-java:3.1.0")
    implementation("org.slf4j:slf4j-api:2.0.17")
}

// Toggle with: gradlew test -PverboseTests=true
val verboseTests: Boolean =
    (project.findProperty("verboseTests")?.toString()?.toBooleanStrictOrNull()) ?: false

tasks.test {
    useJUnitPlatform {
        if (project.hasProperty("excludeIntegration")) {
            excludeTags("integration")
        }
    }

    systemProperty("java.awt.headless", "true")

    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = verboseTests
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }

    if (verboseTests) {
        val green = "\u001B[32m"
        val red = "\u001B[31m"
        val yellow = "\u001B[33m"
        val reset = "\u001B[0m"

        addTestListener(object : TestListener {
            override fun beforeTest(descriptor: TestDescriptor) {}
            override fun beforeSuite(suite: TestDescriptor) {}
            override fun afterSuite(suite: TestDescriptor, result: TestResult) {}

            override fun afterTest(descriptor: TestDescriptor, result: TestResult) {
                val status = when (result.resultType) {
                    TestResult.ResultType.SUCCESS -> "${green}PASSED${reset}"
                    TestResult.ResultType.FAILURE -> "${red}FAILED${reset}"
                    TestResult.ResultType.SKIPPED -> "${yellow}SKIPPED${reset}"
                }
                println("${descriptor.className} > ${descriptor.displayName} $status")
            }
        })
    }
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

    // ensure the JAR exposes Implementation-Version for runtime reads
    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version
        )
    }

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
