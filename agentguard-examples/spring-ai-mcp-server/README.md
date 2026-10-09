# Spring AI + real MCP transport + reusable approvals

This example exercises **0.2.0 development code**, not the published
0.1.0 release. It uses Spring Boot 3.5.7, Spring AI 1.1.0, MCP Java SDK 0.16.0,
Java 21, Spring Security HTTP Basic, H2, and the optional AgentGuard approval and
Spring AI modules. No LLM, API key, Docker, or external database is needed.

## Run in two terminals

From the repository root, with Maven using JDK 21+:

```shell
mvn clean install
mvn -f agentguard-examples/spring-ai-mcp-server/pom.xml verify
java -jar agentguard-examples/spring-ai-mcp-server/target/spring-ai-mcp-server-1.0.0-SNAPSHOT.jar --debug=false
```

In a second terminal, from the repository root:

```shell
mvn -f agentguard-examples/spring-ai-mcp-server/pom.xml org.codehaus.mojo:exec-maven-plugin:3.5.0:java -Dexec.mainClass=io.agentguard.mcpdemo.DemoClient
```

In PowerShell, quote Maven properties containing dots:

```powershell
mvn -f agentguard-examples/spring-ai-mcp-server/pom.xml org.codehaus.mojo:exec-maven-plugin:3.5.0:java '-Dexec.mainClass=io.agentguard.mcpdemo.DemoClient'
```

The server listens on **http://localhost:8082/mcp** using Streamable HTTP.
The client initializes real MCP connections, lists the tools, reads development
order 1, attempts a denied production read, requests a production refund, then
uses a different authenticated approver before executing the refund.

Watch the server's JSON audit logs: `token` is `[HIDDEN]`; authorization and
execution records have correlation IDs and policy content revisions. Restart
the server to reset the H2 data before repeating the full refund walkthrough.

## Security boundary

Accounts `developer`, `operator`, and `approver` use `demo-pass`. Their identities
are held in a trusted server registry, valid for eight hours from startup. The
HTTP principal selects the registry identity. Production integrations should
use verified bearer tokens/TLS and an identity provider with appropriate expiry
and revocation behavior.

`WebMvcStreamableServerTransportProvider.contextExtractor` captures the verified
identity on each HTTP request. The SDK carries it across transport threads;
`GuardedToolCallback` reads it from the MCP exchange. Neither model-supplied
roles nor model-supplied environments change the trusted identity/environment.
Environment comes from the order's H2 row.

Only wrapped callbacks are registered on the MCP server. The callback wrapper
checks policy before invoking the actual operation, so it does not depend on
Spring proxy self-invocation behavior. Tool schemas/metadata and execution
context are preserved. MCP denial/approval are tool execution errors with
`isError=true`, as produced by Spring AI's MCP adapter; they are not invented
transport-level JSON-RPC errors. The separate `agentguard-mcp` mapper remains
available for applications choosing their own error envelope.

This machine-client example uses stateless Basic authentication, no cookie-based
login, and JSON-only approval POSTs. CSRF is excluded for `/mcp` and `/api/**`;
do not copy that exclusion into the session-based H2 dashboard, which retains
CSRF protection. No permissive CORS configuration is installed.

## Reusable approval flow

| HTTP action | Required identity | Effect |
| --- | --- | --- |
| `POST /api/approvals/request` with `{"orderId":2}` | operator | Creates a five-minute ticket only if policy returns APPROVAL_REQUIRED |
| `POST /api/approvals/{id}/approve` with `{}` | approver | Authorizes `agentguard.approval.approve`; self-approval is forbidden |
| `POST /api/approvals/{id}/execute` with the original JSON | original operator | Rechecks policy and request binding, atomically consumes the ticket, then executes SQL |

The library binds the authenticated identity/session, action, arguments, resource,
environment, and policy fingerprint. Changed arguments, changed policy, expired
identity/ticket, replay, and insufficient permissions are rejected. Invocation
uses an immutable argument snapshot. Ticket consumption happens before execution;
a failed/crashed operation does not make the ticket reusable. This is at-most-once
admission, not a distributed exactly-once transaction guarantee.

`InMemoryApprovalStore` is a bounded single-process reference implementation.
Implement `ApprovalStore.update` atomically in your shared database for multiple
instances, and coordinate business idempotency/transactions at the application
boundary. Expired-ticket cleanup is explicit via `removeExpired`; schedule it for
long-running applications. The demo stores at most 10,000 tickets and resets on
restart.

## Tests

`mvn verify` starts an embedded server on a random port and uses real MCP clients.
It tests authenticated transport identity propagation, tool discovery, allowed
execution, denial, approval-required blocking, redaction, unauthenticated HTTP
rejection, and the reusable approval API's request binding and replay prevention.

See [why-agentguard.md](../../why-agentguard.md) for the design rationale.
