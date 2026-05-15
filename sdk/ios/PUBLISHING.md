# Publishing the iOS Access SDK

The iOS SDK is distributed as a [Swift Package](https://www.swift.org/documentation/package-manager/). Internal consumers add it to their Xcode projects via Swift Package Manager (SPM) pointing at the canonical Git URL. There is no separate package-registry server to operate — SPM resolves a Swift Package directly from any Git host that publishes annotated tags.

## Coordinates

| Field | Value |
|-------|-------|
| Git URL | `https://github.com/kennguy3n/cautious-fishstick.git` |
| Package name | `ShieldNetAccess` |
| Library product | `ShieldNetAccess` |
| Tag prefix | `sdk-ios-v` |
| Current version | `0.1.0` |

Because the repository contains other code besides the Swift package, consumers point SPM at the **monorepo Git URL** and SPM walks down to `sdk/ios/Package.swift` automatically — the manifest declares `path: "Sources/ShieldNetAccess"` so the package locates its sources relative to its own directory.

## Release flow

1. Bump the version constant in the changelog header of `sdk/ios/CHANGELOG.md` (newest entry on top).
2. Open a PR that includes the changelog bump and any code changes for the release. Land the PR.
3. From `main` (after the PR merges), tag the release commit:
   ```bash
   git tag -a sdk-ios-v0.2.0 -m "iOS Access SDK 0.2.0"
   git push origin sdk-ios-v0.2.0
   ```
4. The `sdk-ios-release` workflow (`.github/workflows/sdk-ios-release.yml`) triggers on tags matching `sdk-ios-v*` and:
   1. Runs `swift package describe` against `sdk/ios/` to confirm the manifest parses.
   2. Runs `swift test --package-path sdk/ios` (best-effort; macOS-only matrix entry) to confirm the contract tests still pass.
   3. Creates a GitHub Release whose tag is the source tag and whose body is the corresponding `sdk/ios/CHANGELOG.md` entry.
5. SPM consumers update their `Package.swift` dependency entry to:
   ```swift
   .package(
       url: "https://github.com/kennguy3n/cautious-fishstick.git",
       from: "0.2.0"
   )
   ```
   or pin to the exact tag:
   ```swift
   .package(
       url: "https://github.com/kennguy3n/cautious-fishstick.git",
       exact: "0.2.0"
   )
   ```

## Verifying resolution from a clean Swift project

The contract test is documented here so anyone can repeat it locally:

```bash
mkdir -p /tmp/sdk-ios-smoke
cd /tmp/sdk-ios-smoke
swift package init --type executable --name smoke
cat > Package.swift <<'SWIFT'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "smoke",
    platforms: [.macOS(.v12)],
    dependencies: [
        .package(url: "https://github.com/kennguy3n/cautious-fishstick.git", from: "0.1.0"),
    ],
    targets: [
        .executableTarget(
            name: "smoke",
            dependencies: [
                .product(name: "ShieldNetAccess", package: "cautious-fishstick"),
            ]
        ),
    ]
)
SWIFT

cat > Sources/smoke/main.swift <<'SWIFT'
import ShieldNetAccess

let _: AccessSDKClient.Type? = nil
print("ShieldNetAccess resolved")
SWIFT

swift build
.build/debug/smoke
```

Expected output:

```
ShieldNetAccess resolved
```

## Pre-release checklist

- [ ] `swift package describe --package-path sdk/ios` exits 0.
- [ ] `swift test --package-path sdk/ios` exits 0 on macOS.
- [ ] `bash scripts/check_no_model_files.sh` passes (no `.mlmodel` / `.tflite` / `.onnx` / `.gguf` under `sdk/`).
- [ ] `sdk/ios/CHANGELOG.md` has a new entry on top.
- [ ] `docs/sdk.md` "Versioning" table is updated.

## Notes on internal-only consumers

The repository is private. Consumers must have `read` access to `kennguy3n/cautious-fishstick` and configure their CI to authenticate to the Git host (Xcode Cloud / Jenkins / Bitrise all support either an SSH deploy key or a Personal Access Token). SPM honours the standard Git auth mechanisms — no Swift-specific token configuration is required.
