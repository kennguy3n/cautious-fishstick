/*
 * build.gradle.kts — Android Access SDK library module.
 *
 * Provides the JVM compilation surface for the OkHttp-backed
 * AccessSDKClient. The module deliberately does NOT depend on the
 * Android Gradle Plugin so it can be built / tested on a plain JDK
 * in CI without the Android SDK installed. Host apps that want an
 * AAR can re-publish through their own Android module.
 */
plugins {
    kotlin("jvm") version "1.9.22"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // org.json is required for the manual JSON parsing path. On
    // Android it ships with the platform; in JVM tests we pull it
    // in from Maven.
    implementation("org.json:json:20240303")

    testImplementation("org.jetbrains.kotlin:kotlin-test:1.9.22")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:1.9.22")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.7.3")
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
}

sourceSets {
    main {
        kotlin.srcDirs("src/main/kotlin")
    }
    test {
        kotlin.srcDirs("src/test/kotlin")
    }
}
