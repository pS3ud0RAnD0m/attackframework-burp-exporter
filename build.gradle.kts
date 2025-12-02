import org.gradle.api.tasks.testing.TestDescriptor
import org.gradle.api.tasks.testing.TestListener
import org.gradle.api.tasks.testing.TestResult
import org.gradle.jvm.tasks.Jar
import org.gradle.testing.jacoco.tasks.JacocoReport
import org.gradle.external.javadoc.StandardJavadocDocletOptions

plugins {
    id("java")
    id("jacoco")
    id("com.github.ben-manes.versions") version "0.53.0"
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
    // --- compileOnly ---
    compileOnly(libs.montoya)
    compileOnly(libs.logbackClassic)

    // --- implementation ---
    implementation(libs.jacksonCore)
    implementation(libs.jacksonDatabind)
    implementation(libs.miglayoutSwing)
    implementation(libs.jakartaJsonApi)
    implementation(libs.glassfishJson)
    implementation(libs.opensearchJava)
    implementation(libs.slf4jApi)

    // --- testImplementation ---
    testImplementation(platform(libs.junitBom))
    testImplementation(libs.junitJupiter)
    testImplementation(libs.mockitoCore)
    testImplementation(libs.mockitoJunitJupiter)
    testImplementation(libs.assertjCore)

    // --- testRuntimeOnly ---
    testRuntimeOnly(libs.junitJupiterEngine)
    testRuntimeOnly(libs.junitPlatformLauncher)

    // --- runtimeOnly ---
    runtimeOnly(libs.logbackClassic)
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
    systemProperty("attackframework.version", project.version.toString())

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

tasks.withType<Javadoc>().configureEach {
    isFailOnError = false
    @Suppress("UNCHECKED_CAST")
    (options as StandardJavadocDocletOptions).apply {
        addBooleanOption("Xdoclint:none", true)
        addBooleanOption("quiet", true)
        encoding = "UTF-8"
        charSet = "UTF-8"
        docEncoding = "UTF-8"
        locale = "en_US"
        links("https://docs.oracle.com/en/java/javase/21/docs/api/")
    }
}

tasks.register<Jar>("fatJar") {
    group = "build"
    description = "Assembles a fat JAR containing compiled classes and runtime dependencies."

    archiveBaseName.set(project.property("archivesBaseName").toString())
    archiveVersion.set(project.property("version").toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

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
