/*
 * build.gradle.kts — Android Access SDK library module.
 *
 * Provides the JVM compilation surface for the OkHttp-backed
 * AccessSDKClient. The module deliberately does NOT depend on the
 * Android Gradle Plugin so it can be built / tested on a plain JDK
 * in CI without the Android SDK installed. Host apps that want an
 * AAR can re-publish through their own Android module.
 *
 * Publishing — see sdk/android/PUBLISHING.md for the release flow.
 * Coordinates are `com.shieldnet360.access:access-sdk:<version>`.
 * The artifact is published to the internal Maven registry via the
 * `maven-publish` plugin; the registry URL and credentials come from
 * Gradle properties so CI can override them without changing this
 * file. The default repository targets GitHub Packages for
 * `kennguy3n/cautious-fishstick`, which is the internal mirror used
 * across the SN360 monorepo.
 */
plugins {
    kotlin("jvm") version "1.9.22"
    `maven-publish`
    `java-library`
}

group = "com.shieldnet360.access"
version = (findProperty("sdk.android.version") as String?) ?: "0.1.0"

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

java {
    withSourcesJar()
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

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
            artifactId = "access-sdk"
            pom {
                name.set("ShieldNet 360 Access SDK (Android)")
                description.set(
                    "Kotlin / JVM REST client for the ShieldNet 360 Access Platform. " +
                        "Thin client — no on-device inference."
                )
                url.set("https://github.com/kennguy3n/cautious-fishstick")
                licenses {
                    license {
                        name.set("UNLICENSED — internal use only")
                    }
                }
                scm {
                    url.set("https://github.com/kennguy3n/cautious-fishstick")
                    connection.set("scm:git:https://github.com/kennguy3n/cautious-fishstick.git")
                    developerConnection.set(
                        "scm:git:ssh://git@github.com/kennguy3n/cautious-fishstick.git"
                    )
                }
            }
        }
    }

    repositories {
        maven {
            name = "GitHubPackages"
            url = uri(
                (findProperty("sdk.android.maven.url") as String?)
                    ?: "https://maven.pkg.github.com/kennguy3n/cautious-fishstick"
            )
            credentials {
                username = (findProperty("sdk.android.maven.user") as String?)
                    ?: System.getenv("MAVEN_USERNAME")
                            ?: System.getenv("GITHUB_ACTOR")
                password = (findProperty("sdk.android.maven.token") as String?)
                    ?: System.getenv("MAVEN_PASSWORD")
                            ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
