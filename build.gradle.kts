plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "ai.attackframework.vectors.sources.burp"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.6")

    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")

    implementation("org.opensearch.client:opensearch-java:2.14.0")
    implementation("org.opensearch.client:opensearch-rest-client:2.14.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.1")
    implementation("org.apache.httpcomponents:httpcore:4.4.16")
}

tasks.test {
    useJUnitPlatform()
}

tasks {
    shadowJar {
        archiveClassifier.set("")
    }
    build {
        dependsOn(shadowJar)
    }
}