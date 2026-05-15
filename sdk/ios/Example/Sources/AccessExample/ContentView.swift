//
// ContentView.swift — minimal SwiftUI sample exercising the
// `URLSessionAccessSDKClient` against `ztna-api`.
//
// The view depends on the `AccessSDKClient` protocol, not the
// concrete class — this matches the DI pattern documented in
// `docs/sdk.md`. Production hosts substitute a custom
// client (e.g. with auth-aware URLSession) without touching the UI.
//

import SwiftUI
import ShieldNetAccess

/// The sample-app screen. Press a row to invoke the corresponding
/// SDK method and display the result / error.
@available(iOS 16.0, macOS 13.0, *)
public struct ContentView: View {
    private let client: AccessSDKClient
    @State private var output: String = "Tap an action."

    public init(client: AccessSDKClient) {
        self.client = client
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("ShieldNet Access SDK Sample")
                .font(.title)

            Button("Create request") { Task { await runCreate() } }
            Button("List requests") { Task { await runListRequests() } }
            Button("List grants") { Task { await runListGrants() } }
            Button("Explain policy") { Task { await runExplain() } }
            Button("Suggest resources") { Task { await runSuggest() } }

            ScrollView {
                Text(output)
                    .font(.system(.body, design: .monospaced))
                    .padding(.top)
            }
        }
        .padding()
    }

    private func runCreate() async {
        do {
            let req = try await client.createRequest(
                resource: "projects/foo",
                role: "viewer",
                justification: "sample-app demo"
            )
            output = "createRequest -> \(req.id) state=\(req.state.rawValue)"
        } catch {
            output = "createRequest error: \(error)"
        }
    }

    private func runListRequests() async {
        do {
            let items = try await client.listRequests(state: nil, requester: nil, resource: nil)
            output = "listRequests -> count=\(items.count)"
        } catch {
            output = "listRequests error: \(error)"
        }
    }

    private func runListGrants() async {
        do {
            let items = try await client.listGrants(userID: nil, connectorID: nil)
            output = "listGrants -> count=\(items.count)"
        } catch {
            output = "listGrants error: \(error)"
        }
    }

    private func runExplain() async {
        do {
            let exp = try await client.explainPolicy(policyID: "pol_sample")
            output = "explainPolicy -> \(exp.summary)"
        } catch {
            output = "explainPolicy error: \(error)"
        }
    }

    private func runSuggest() async {
        do {
            let items = try await client.suggestResources()
            output = "suggestResources -> count=\(items.count)"
        } catch {
            output = "suggestResources error: \(error)"
        }
    }
}
