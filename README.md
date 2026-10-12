# AgentGuard

**Tool-level authorization, request-bound approvals, and sanitized audit trails for Java agents.**

[![CI](https://github.com/Amaljeevs/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Amaljeevs/agentguard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org/projects/jdk/21/)

AgentGuard evaluates who may perform an action on a resource in a particular
environment, stops denied or unapproved calls, and records structured evidence.
OAuth/OIDC and Spring Security authenticate the caller and validate JWTs;
AgentGuard governs the business action that an authenticated agent proposes.
Read [why-agentguard.md](why-agentguard.md) for the comparison, supported use cases,
and future directions.

**Release status:** `0.1.0` is published on Maven Central. The code on this branch
is **`0.2.0`, prepared for release; publication pending**. New approval and Spring AI modules require a
local build. See [CHANGELOG.md](CHANGELOG.md) for behavior changes and migration.

## Try a runnable app

### Published release: H2 browser dashboard

With Java 21+ and Maven 3.6.3+:

```shell
cd agentguard-examples/h2-orders-app
mvn verify
java -jar target/h2-orders-app-1.0.0-SNAPSHOT.jar --debug=false
```

Open **http://localhost:8080**. Users `developer`, `operator`, `approver`, and
`auditor` all use password `demo-pass`. The app has seeded H2 orders, real SQL,
production refund approvals, and nested secret redaction. Data resets on restart.
On Windows, `./run.ps1` builds and starts it; `./demo.ps1` runs the API walkthrough.

This app remains pinned to the published release. Its approval workflow is
application code. [Full instructions](agentguard-examples/h2-orders-app/README.md).
For a smaller console demo, see the
[published dependency example](agentguard-examples/published-dependency-example/README.md).

### Development version: Spring AI + real MCP + reusable approvals

From the repository root:

```shell
mvn clean install
mvn -f agentguard-examples/spring-ai-mcp-server/pom.xml verify
java -jar agentguard-examples/spring-ai-mcp-server/target/spring-ai-mcp-server-1.0.0-SNAPSHOT.jar --debug=false
```

The MCP server listens at **http://localhost:8082/mcp**. In another terminal:

```shell
mvn -f agentguard-examples/spring-ai-mcp-server/pom.xml org.codehaus.mojo:exec-maven-plugin:3.5.0:java "-Dexec.mainClass=io.agentguard.mcpdemo.DemoClient"
```

The client demonstrates an allowed read, a denied production read, an approval
requirement, a separate approver, and single-use approved execution. No model
API key or external database is required. This example consumes the new library
modules and propagates authenticated identity over real Streamable HTTP MCP.
[Full instructions](agentguard-examples/spring-ai-mcp-server/README.md).

## Integrate the development starter

Until 0.2.0 is published, install it locally, then add this dependency to a Spring Boot app:

```xml
<dependency>
    <groupId>io.github.amaljeevs</groupId>
    <artifactId>agentguard-spring-boot-starter</artifactId>
    <version>0.2.0</version>
</dependency>
```

Use `0.1.0` to consume the published release, with the limitations listed in the
changelog. Configure authentication through Spring Security or supply a trusted
`AgentIdentityResolver`. Never accept identity/roles directly from model arguments.

Create `src/main/resources/agentguard-policy.yaml`:

```yaml
version: "1.0"
metadata:
  name: order-governance
  version: "2026-10"
roles:
  operator:
    permissions: [orders.read, orders.refund]
rules:
  - id: production-refund-review
    effect: APPROVAL_REQUIRED
    risk: HIGH
    target:
      actions: [orders.refund]
      conditions:
        environment:
          equals: production
```

Protect Spring-managed service methods:

```java
@AgentAuthorize(action = "kubernetes.deploy", resourceType = "cluster",
    resource = "#cluster", environment = "production")
public void deploy(String cluster) {
    // Application SQL/client operation, executed only after authorization allows it.
}
```

A matching production approval rule blocks the method with
`AgentApprovalRequiredException`. Use the optional `agentguard-approval` module
for approval issuance, separate approver checks, and bound execution. The
annotation does not automatically implement a review UI or approval storage.
Calls must go through the Spring proxy; self-invocation is not intercepted.
Use `GuardedToolCallback` for the Spring AI execution boundary.

```yaml
agentguard:
  policy-location: classpath:agentguard-policy.yaml
  audit:
    enabled: true
    mask-token: "[HIDDEN]"
    sensitive-keys: [customerEmail, internalNote]
    failure-mode: FAIL_CLOSED
```

The default JSON audit logger is `io.agentguard.audit.json`. It records a SHA-256
arguments fingerprint, delegation chain, policy version/hash, risk and trace ID;
it does not emit raw arguments. Authorization and execution outcomes are separate,
correlated events. `BEST_EFFORT` is available when continuing after an audit sink
failure is an explicit application decision. Post-execution logging failure may
occur after side effects; applications still need idempotency.

## Modules

| Module | Responsibility |
| --- | --- |
| `agentguard-core` | Dependency-free Java policy engine, identity/request models, permission matching, content revisions, trusted delegation lookup |
| `agentguard-policy` | YAML loading/validation and declarative policy test CLI |
| `agentguard-audit` | Structured sanitization, `@Sensitive`, JSON/SLF4J/composite/bounded-memory publishers, execution lifecycle |
| `agentguard-spring` | `@AgentAuthorize`, fail-closed expression resolution, Spring Security identity bridge |
| `agentguard-spring-boot-starter` | Default beans, configuration properties, required AOP/security-core dependencies |
| `agentguard-mcp` | Authorization-exception to error-object mapping; no implicit transport registration |
| `agentguard-approval` | Optional exact-request approvals, expiration, rejection, atomic store SPI and reference in-memory implementation |
| `agentguard-spring-ai` | Optional ToolCallback and ToolCallbackProvider enforcement wrappers |
| `agentguard-spring-web` | Optional JSON `POST /v1/authorize` adapter for language-neutral clients |

`agentguard-approval` and `agentguard-spring-ai` are new in the development version.
The starter does not pull in an MCP server or an LLM provider.

## Policy semantics

Identity validity and explicit DENY rules are checked first. An explicit ALLOW or
role/direct permission must grant the action before a matching approval rule can
return APPROVAL_REQUIRED. Otherwise the result is DENY. For delegation, the
request must be eligible for both child and every trusted ancestor. The child's
complete effective permission set must also be a conservative subset of its
parent's authority. Unknown parents, inconsistent chains, privilege expansion,
cycles, excessive depth and invalid temporal bounds deny.

A configured expression that cannot resolve is denied; it does not silently
change the environment. Use trusted resource metadata for environments. The
core evaluator accepts an explicit evaluation timestamp for deterministic tests;
production callers must supply a trusted current clock.

See the [policy specification](specification/docs/POLICY_SPECIFICATION.md) and
[security boundaries](SECURITY.md).

## Architecture and trust flow

```text
OAuth/OIDC, mTLS or SPIFFE verifier
                |
                v
       AgentIdentityResolver  ---- trusted sub/client_id/actor/tenant/scopes
                |
                v
  AuthorizationRequest (identity + action + resource + canonical arguments + context)
                |
                v
     PolicyEngine  ---- DENY / ALLOW / APPROVAL_REQUIRED + policy/risk/trace evidence
          |                                  |
          |                                  v
          |                         ApprovalService (bound SHA-256,
          |                         expiry, atomic single use)
          v                                  |
  guarded method/tool execution <------------+
                |
                v
       sanitized audit evidence
```

`AgentIdentityResolver` is the trust boundary. The built-in JWT claim mapper only
accepts `VerifiedClaims`, which an upstream Keycloak, Entra, Spring Security,
SPIFFE-JWT or custom verifier must produce after validating signature, issuer,
audience and token lifetime. It maps `sub`, `client_id`, `actor`, `tenant`/`tid`,
`scope`/`scp`, roles and `delegation_chain`. Request JSON and model tool arguments
never supply effective agent IDs, roles or permissions.

For plain Java use, no server is required:

```java
AgentGuard agentGuard = new AgentGuard(policyEngine, trustedIdentityResolver);
AuthorizationDecision decision = agentGuard.authorize(request);
```

The resolver-backed facade replaces any identity carried by `request` with the
current verified identity. The one-argument constructor remains available for
trusted in-process requests that were already constructed from verified data.

The optional `agentguard-spring-web` module exposes the same engine to other
languages. Applications register `AgentGuardAuthorizationApi` and
`AuthorizationController` with their trusted identity resolver. `principal` is
only checked against that resolved identity; it never grants authority.

```http
POST /v1/authorize
Content-Type: application/json

{
  "principal": "deploy-agent",
  "action": "kubernetes.deploy",
  "resource": {"type": "cluster", "id": "prod-a", "tags": {}},
  "arguments": {"image": "orders:v2"},
  "context": {"environment": "production", "traceId": "trace-123"}
}
```

```json
{
  "decision": "APPROVAL_REQUIRED",
  "reason": "Production deployment requires review",
  "matchedPolicy": "cluster-governance",
  "matchedRule": "prod-deploy-review",
  "policyVersion": "2026-10",
  "policyHash": "...",
  "risk": "CRITICAL",
  "approvalRequestId": "...",
  "traceId": "trace-123"
}
```

Spring AI callbacks can route approval-required calls directly into the approval
module by using the `GuardedToolCallback` constructor that accepts an
`ApprovalService` and TTL. The real callback stays blocked; its exception carries
the bound approval request ID. MCP remains a small error adapter and is absent
from the core engine.

## Threat model

AgentGuard is designed to stop forged payload identities, default-allow gaps,
delegation privilege expansion, altered or replayed approvals, unreviewed tool
execution and secret exposure through its standard audit publisher. It assumes
the application protects policy files, uses a real token/workload-identity
verifier, resolves resource facts such as production environment from trusted
data, registers only guarded callbacks, and implements atomic approval storage
for clustered deployments.

It does not validate credentials itself, sandbox arbitrary code, detect prompt
injection, make remote side effects exactly once, or sanitize logs outside the
AgentGuard audit pipeline. OAuth/JWT proves who presented a valid credential;
AgentGuard decides whether that verified identity may perform this exact action
on this resource now, and records the decision evidence.

## Tests, policy checks, and benchmarks

```shell
mvn clean verify
mvn -f agentguard-policy/pom.xml org.codehaus.mojo:exec-maven-plugin:3.5.0:java "-Dexec.mainClass=io.agentguard.policy.testing.PolicyTestCli" "-Dexec.args=agentguard-examples/spring-ai-mcp-server/src/main/resources/agentguard-policy.yaml specification/examples/policy-scenarios.json"
```

Run the CLI from the repository root after `mvn install`. It prints decisions,
matched rules, and policy revision; mismatched expectations return a failing
process status. CI also builds both independent published-release examples and
runs the development MCP network tests.

[The JMH harness](benchmarks/README.md) measures evaluation and sanitization for
specified workloads. Report hardware, JDK and workload with results; microbenchmarks
are not end-to-end latency guarantees.

| Integration | Tested baseline |
| --- | --- |
| Core, audit, policy, approvals | Java 21 |
| Spring starter and published consumer examples | Spring Boot 3.3.4 |
| New Spring AI/MCP example | Spring Boot 3.5.7, Spring AI 1.1.0, MCP Java SDK 0.16.0 |

Other versions are not claimed compatible until tested. Current audit/approval
changes are documented breaking behavior changes for consumers of 0.1.0.

## Boundaries and future work

Structured redaction does not detect every secret in arbitrary text or sanitize
all third-party logs. The reference approval store is not shared/durable. There
is no built-in risk scoring, universal prompt-injection protection, agent sandbox,
or Python/TypeScript/Go runtime. See [why-agentguard.md](why-agentguard.md) for
implemented capabilities and explicitly future work.

## Maintainer and security reports

Maintained by **Amal jeev s** ([@Amaljeevs](https://github.com/Amaljeevs)).
Contact [amaljeevs3739@gmail.com](mailto:amaljeevs3739@gmail.com).
Report vulnerabilities privately using [SECURITY.md](SECURITY.md).

## Publishing

The group ID is `io.github.amaljeevs`. Publishing is a maintainer release action:
select an unused non-SNAPSHOT release version, run all checks, configure Central
credentials/signing, then use `./mvnw clean deploy -P release` (Windows:
`./mvnw.cmd clean deploy -P release`). Version `0.2.0` is
prepared for publishing; this does not itself deploy artifacts or overwrite 0.1.0.

To publish through GitHub Actions, run **Publish to Maven Central** on the updated
`main` branch, or publish a release whose tag points to the release-version commit.
Re-running an older failed workflow uses its original commit, which may still
contain a SNAPSHOT version. The workflow intentionally rejects those versions.

Set the `GPG_PRIVATE_KEY` Actions secret to the complete ASCII-armored private
key export, including its BEGIN/END lines. The import step accepts actual line
breaks or literal `\n` sequences and rejects malformed keys without logging
their contents. Never paste private keys into issues or build logs.

CI and publishing use the Maven wrapper pinned to 3.9.9. Use the wrapper for
releases: Maven 3.10 can leave `maven-metadata-local.xml` in the publishing
plugin's staging directory, producing Central's misleading missing-POM error.
A failed publish preserves the bundle as a workflow artifact for inspection.

## License

[Apache License 2.0](LICENSE). Copyright (c) 2026 Amal Jeev S.
