//
// AccessExampleApp.swift — SwiftUI app entry point that wires a
// real `URLSessionAccessSDKClient` and injects it into ContentView.
//

import SwiftUI
import ShieldNetAccess

@available(iOS 16.0, macOS 13.0, *)
@main
struct AccessExampleApp: App {
    private let client: AccessSDKClient = URLSessionAccessSDKClient(
        baseURL: Config.baseURL,
        authTokenProvider: { Config.bearerToken }
    )

    var body: some Scene {
        WindowGroup {
            ContentView(client: client)
        }
    }
}
