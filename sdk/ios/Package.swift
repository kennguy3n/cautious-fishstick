// swift-tools-version:5.7
//
// ShieldNetAccess — iOS Access SDK (Swift Package).
//
// REST-only client for the ShieldNet 360 Access Platform `ztna-api`. There is
// **no on-device inference**, no `CoreML` import, no `MLX` import, no bundled
// model weights (`.mlmodel`, `.tflite`, `.onnx`, `.gguf`). Every "AI" call is
// a REST call to the server-side `access-ai-agent` over HTTPS. See
// `docs/architecture.md` §11.1 and `docs/sdk.md`.
//
// This manifest is intentionally minimal — the package only ships the
// `AccessSDKClient` protocol and the request / response model types. Concrete
// `URLSession` implementations live in the host application.

import PackageDescription

let package = Package(
    name: "ShieldNetAccess",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "ShieldNetAccess",
            targets: ["ShieldNetAccess"]
        ),
    ],
    targets: [
        .target(
            name: "ShieldNetAccess",
            path: "Sources/ShieldNetAccess"
        ),
        .testTarget(
            name: "ShieldNetAccessTests",
            dependencies: ["ShieldNetAccess"],
            path: "Tests/ShieldNetAccessTests"
        ),
    ]
)
