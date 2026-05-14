# Publishing the Android Access SDK

The Android SDK is a Kotlin / JVM library distributed as a Maven artifact. The default publishing target is the GitHub Packages Maven registry for `kennguy3n/cautious-fishstick`, but the registry URL and credentials are driven by Gradle properties so any internal Maven repository (Artifactory, Nexus, Sonatype Nexus Repository Manager) can be substituted without editing `build.gradle.kts`.

## Coordinates

| Field | Value |
|-------|-------|
| Group ID | `com.shieldnet360.access` |
| Artifact ID | `access-sdk` |
| Current version | `0.1.0` |
| Repository (default) | `https://maven.pkg.github.com/kennguy3n/cautious-fishstick` |
| Tag prefix | `sdk-android-v` |

Consumers declare the dependency in their host app:

```kotlin
// settings.gradle.kts — register the GitHub Packages repo
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
        maven {
            name = "ShieldNet360GitHubPackages"
            url = uri("https://maven.pkg.github.com/kennguy3n/cautious-fishstick")
            credentials {
                username = providers.gradleProperty("gpr.user").orNull
                    ?: System.getenv("GITHUB_ACTOR")
                password = providers.gradleProperty("gpr.token").orNull
                    ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.shieldnet360.access:access-sdk:0.1.0")
}
```

## Release flow

1. Bump the entry at the top of `sdk/android/CHANGELOG.md`.
2. Open a PR with the changelog and any code changes; land it.
3. From `main`, tag the release commit:
   ```bash
   git tag -a sdk-android-v0.2.0 -m "Android Access SDK 0.2.0"
   git push origin sdk-android-v0.2.0
   ```
4. The `sdk-android-release` workflow (`.github/workflows/sdk-android-release.yml`) triggers on tags matching `sdk-android-v*` and:
   1. Reconstructs the version from the tag (`sdk-android-v0.2.0` → `0.2.0`).
   2. Runs `./gradlew :build :test` inside `sdk/android/` to confirm the library still compiles and the contract tests still pass.
   3. Runs `./gradlew :publishLibraryPublicationToGitHubPackagesRepository` with the version supplied via `-Psdk.android.version`. Credentials come from `MAVEN_USERNAME` / `MAVEN_PASSWORD` env vars (or `GITHUB_ACTOR` / `GITHUB_TOKEN` as the GitHub Packages fallback).
5. Verify the artifact landed:
   ```bash
   curl -fsSL \
     -u "$GITHUB_ACTOR:$GITHUB_TOKEN" \
     https://maven.pkg.github.com/kennguy3n/cautious-fishstick/com/shieldnet360/access/access-sdk/0.2.0/access-sdk-0.2.0.pom
   ```

## Verifying resolution from a clean Gradle project

```bash
mkdir -p /tmp/sdk-android-smoke && cd /tmp/sdk-android-smoke
cat > settings.gradle.kts <<'KTS'
rootProject.name = "smoke"
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven {
            name = "ShieldNet360GitHubPackages"
            url = uri("https://maven.pkg.github.com/kennguy3n/cautious-fishstick")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
KTS

cat > build.gradle.kts <<'KTS'
plugins { kotlin("jvm") version "1.9.22" }
repositories { mavenCentral() }
dependencies {
    implementation("com.shieldnet360.access:access-sdk:0.1.0")
}
kotlin { jvmToolchain(17) }
KTS

mkdir -p src/main/kotlin
cat > src/main/kotlin/Main.kt <<'KT'
import com.shieldnet360.access.AccessSDKClient
fun main() { println("AccessSDKClient.${'$'}{AccessSDKClient::class.simpleName} resolved") }
KT

./gradlew run
```

Expected output (one of the final lines):

```
AccessSDKClient.AccessSDKClient resolved
```

## Switching to a different Maven registry

Override the URL and credentials at publish time:

```bash
./gradlew :publishLibraryPublicationToGitHubPackagesRepository \
  -Psdk.android.version=0.2.0 \
  -Psdk.android.maven.url=https://artifactory.internal.shieldnet360.example/access-sdk \
  -Psdk.android.maven.user=$ARTIFACTORY_USER \
  -Psdk.android.maven.token=$ARTIFACTORY_TOKEN
```

The Gradle plugin keeps the publication name `GitHubPackages` regardless of URL — it's just a label. Consumers point at whatever URL is configured for them.

## Pre-release checklist

- [ ] `./gradlew :build :test` exits 0 inside `sdk/android/`.
- [ ] `bash scripts/check_no_model_files.sh` passes.
- [ ] `sdk/android/CHANGELOG.md` has a new entry on top.
- [ ] `docs/SDK_CONTRACTS.md` "Versioning" table is updated.
