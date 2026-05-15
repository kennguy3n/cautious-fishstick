# ShieldNet Access Deep Dive

A long-form blog series covering ShieldNet Access — the access management product inside the ShieldNet 360 ecosystem. Posts are split into three audience tracks:

- **Business** — written for SME founders, operations leads, and people-managers. Jargon-free, outcome-focused.
- **Product** — written for IT generalists and admins. Concrete workflows, screenshots-in-words, and the value each capability unlocks.
- **Technical** — written for technical evaluators, integration partners, and security architects. Deep architecture, code references, and integration points.

All user-facing language follows the product-language table in [`docs/overview.md`](../docs/overview.md#product-language) — access rules instead of policies, app connections instead of connectors, access check-ups instead of access reviews, risk level instead of risk score. Technical posts may use the engineering vocabulary but always note the product equivalent on first use.

## Series index

| # | Post | Type | Summary |
|---|------|------|---------|
| 00 | [Introducing ShieldNet Access: Unified Zero Trust Access for the Modern SME](./00-introducing-shieldnet-access.md) | Business + Product | The master intro post — why ShieldNet Access exists, where it fits in ShieldNet 360, and a guided tour of the four product pillars. |
| 01 | [Why SMEs Need Zero Trust — And Why Legacy Tools Fall Short](./01-why-smes-need-zero-trust.md) | Business | The SaaS-sprawl pain that every 50-to-500-person company is feeling, why VPN-shaped IAM tools can't solve it, and what "zero trust for the small team" actually looks like. |
| 02 | [200+ App Connections, One Control Plane](./02-200-app-connections.md) | Product | A walk through the 5-tier app-connection catalogue, the guided setup wizard, encrypted credential storage, and what every app connection gives you on day one. |
| 03 | [Inside the Zero Trust Overlay: How ShieldNet Access Enforces Least-Privilege at the Network Layer](./03-zero-trust-overlay.md) | Technical | Why we chose OpenZiti as the zero-trust dataplane, how Members / Teams / Resources / Access Rules map onto Ziti primitives, the dual-consistency pattern, and the device enrollment flow. |
| 04 | [Access Rules Without the Risk: Draft, Simulate, Promote](./04-access-rules-safe-test.md) | Product | The draft-and-promote workflow that lets you change an access rule without holding your breath — impact analysis, conflict detection, AI risk review, and the one-click "turn the rule on" step. |
| 05 | [AI-Powered Access Intelligence: Risk Scoring, Auto-Certification, and Anomaly Detection](./05-ai-powered-access-intelligence.md) | Technical | The A2A protocol between the Go backend and Python AI agent, the five Tier-1 skills, the best-effort fallback pattern, and the LangGraph workflow engine. |
| 06 | [Automating the Employee Lifecycle: How JML Eliminates Access Drift](./06-jml-automation.md) | Business | Joiner / Mover / Leaver in plain English — what gets provisioned on day one, what gets cleaned up on day last, and how SCIM auto-sync removes the spreadsheet step from offboarding. |
| 07 | [Access Check-Ups: Continuous Certification Without the Spreadsheet](./07-access-checkups.md) | Product | Scheduled campaigns, AI auto-certification of low-risk grants, decision flow, campaign metrics, and the cron scheduler that makes "every 90 days" actually happen. |
| 08 | [The Connector Architecture: Building a Universal Access Fabric](./08-connector-architecture.md) | Technical | The `AccessConnector` interface, optional capability interfaces, the registry pattern, AES-GCM credential management, pagination patterns across 200 providers, and idempotency contracts. |
| 09 | [From Request to Revoke: Making Access Governance Invisible](./09-request-to-revoke.md) | Product | The full access lifecycle as a state machine — request → risk review → workflow routing → approval → provisioning → active → check-up → revoke — across web, iOS, Android, and desktop. |
| 10 | [Runtime Detection Meets Access Control: Closing the Loop with ShieldNet 360](./10-runtime-detection-meets-access.md) | Technical | How ShieldNet Access plugs into ShieldNet Protect and ShieldNet Detect — Sigma rules, Falco DaemonSets, K8s posture, and the closed loop from anomaly to automatic revocation. |

## Where to start

- **You're an SME founder or operations lead.** Read 00, then 01, then 06.
- **You're an IT generalist setting up access for a 50-person team.** Read 00, then 02, then 09, then 07.
- **You're a technical evaluator or integration partner.** Read 00, then 03, then 08, then 05, then 10.

## Reference material

The posts in this series cite four primary docs:

- [`docs/overview.md`](../docs/overview.md) — product overview and design principles.
- [`docs/architecture.md`](../docs/architecture.md) — service topology, request lifecycles, and data model.
- [`docs/connectors.md`](../docs/connectors.md) — per-provider capability matrix for all 200 connectors.
- [`docs/sdk.md`](../docs/sdk.md) — mobile and desktop SDK contract.

Where the implementation differs from these documents, the code is the source of truth and the documents are updated to match.
