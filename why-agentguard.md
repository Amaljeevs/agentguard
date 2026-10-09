# Why AgentGuard?

AgentGuard packages tool-level authorization, human approval, delegation checks,
and sanitized audit records for Java agent applications. It works alongside
Spring Security: Spring establishes trusted identity and secures application
endpoints; AgentGuard applies a consistent governance contract to individual
agent operations.

The value is reusable enforcement and integration. Spring Security can express
fine-grained authorization itself, and teams with existing policy infrastructure
may not need another policy engine.

## The problem it addresses

Consider an agent connected to an order-management MCP server. The same
authenticated connection can request three very different operations:

1. Read a development order: allow it.
2. Read a production order as a developer: deny it.
3. Refund a production order as an operator: require an authorized human to
   approve that exact request before execution.

The application needs to resolve the actual resource and environment, evaluate
permissions, stop execution when necessary, bind any approval to the request,
and retain useful evidence without recording passwords or tokens. Reimplementing
that sequence separately in every tool makes behavior harder to review and test.

AgentGuard provides those building blocks. The model proposes arguments; trusted
application code owns authentication, resource lookup, policy, and execution.
It does not ask a model to decide whether its own operation is safe.

## How this differs from Spring authorization

Spring Security supports request authorization, method authorization, custom
authorization managers, and application-specific checks. `@PreAuthorize` can
already express detailed conditions; it is not limited to coarse role checks.
See the official [method security documentation](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html).

| Concern | Spring Security's role | AgentGuard's contribution |
| --- | --- | --- |
| Authentication | Validate credentials/tokens and establish a principal | Consume a trusted identity; never replace credential validation |
| Endpoint/session security | Request authorization, CSRF, sessions, security context | Reuse those controls around HTTP/MCP endpoints |
| Fine-grained authorization | Method security and extensible authorization managers | A shared agent/action/resource/environment model and declarative policy evaluator |
| Tool invocation | Integrate application authorization with tool code | A Spring AI ToolCallback wrapper that checks immediately before execution |
| Human approval | Build the workflow using application services | Explicit APPROVAL_REQUIRED plus request-bound, expiring, single-use approval primitives |
| Delegation | Model the application's authority relationships | Check each request against the child and every parent resolved from a trusted registry |
| Audit data | Authentication/authorization events and application logging | Structured parameter redaction, policy revision, correlation, and separate execution outcomes |

AgentGuard does not invalidate or bypass Spring method security. Applications
can use both. A method or tool must pass every applicable enforcement layer.

The [Spring AI tool-calling documentation](https://docs.spring.io/spring-ai/reference/api/tools.html)
explains that applications execute tool calls requested by models. That execution
boundary is where AgentGuard's callback adapter belongs. Securing an MCP
transport and authorizing a particular business action are both necessary;
see [Spring AI MCP server documentation](https://docs.spring.io/spring-ai/reference/api/mcp/mcp-server-boot-starter-docs.html).

## What is implemented

**Version boundary:** Maven Central currently has `0.1.0`. This repository's new
capabilities are `0.2.0` development code and require a local build until
a release is published. See [CHANGELOG.md](CHANGELOG.md) for migration details.

| Capability | Published 0.1.0 | Development 0.2.0 |
| --- | --- | --- |
| Java 21 core; roles, direct permissions, wildcard matching | Yes | Yes |
| Environment/resource rules; explicit deny precedence | Yes | Yes |
| Approval-required policy decision | Yes; evaluated before grants | Requires an underlying grant |
| Spring annotation and Boot configuration | Yes | Fail-closed expression handling and configuration fixes |
| Structured audit sanitization | Maps and lists, with null/DTO limitations | Nulls, maps, lists, arrays, records, bean getters, `@Sensitive`, cycle/depth limits |
| Reusable JSON audit logger | Example-only implementation | Library publisher with sanitized parameters/metadata |
| Execution outcome audit | Not provided | Authorization, success and failure events with correlation and policy revision |
| Delegation | Identity metadata only | Per-request ancestor checks through `AgentIdentityLookup` |
| Approval workflow primitives | Example-specific application workflow | Optional `agentguard-approval` module with atomic store SPI |
| MCP integration | Exception-to-error mapping | Mapping plus optional Spring AI callback adapter and real MCP transport example |
| Policy test CLI and benchmark harness | Not provided | Included |

The core remains independent of Spring. Audit, approval, Spring, and Spring AI
integrations are separate modules so applications can choose their dependencies.

## What makes an approval meaningful

An approval must refer to the operation the reviewer actually authorized. The
development approval module binds a ticket to the requester identity/session,
action, structured arguments, resource, environment, and content-based policy
revision. Tickets expire. The approver must have
`agentguard.approval.approve` permission and cannot approve their own request.

Before execution, AgentGuard snapshots the proposed arguments, re-evaluates
current policy, verifies the binding and expiry, and atomically consumes the
ticket. The operation receives the verified immutable argument snapshot.
Changing the order, amount, actor, or policy requires a new approval.

This provides at-most-once admission through the approval service. It does not
promise exactly-once external side effects. If the process crashes after consuming
a ticket, or the business operation fails, applications must reconcile the result
and use business idempotency/transactions where needed. The supplied in-memory
store is single-process; clustered deployments need an atomic shared store.

## What an audit record proves

An AUTHORIZATION record captures a policy decision. EXECUTION_SUCCEEDED means
the wrapped operation returned normally; EXECUTION_FAILED means it threw. Neither
event alone proves that a remote system committed a transaction. Correlation IDs
connect the records, and policy fingerprints identify the evaluated rules.

Sanitization runs before publishers receive standard audit events. The reusable
JSON publisher also sanitizes at its own boundary. Applications can add sensitive
keys or use `@Sensitive` on supported DTO accessors/components. Unsupported
objects and excessive/cyclic traversal are masked rather than rendered blindly.

This is structured redaction, not a universal secret detector. A secret embedded
in an ordinary product description is still an ordinary string. Arbitrary HTTP,
SQL, exception, and third-party logs are outside this pipeline. Choose what data
to log and configure other logging systems independently.

## When to use it

AgentGuard fits a Java/Spring team that exposes agent-callable operations and
wants consistent policy decisions, approval semantics and sanitized audit output
without writing the integration for every tool. The examples are useful starting
points for internal database assistants, infrastructure tools and support agents.

It may add unnecessary complexity when normal endpoint/method authorization is
sufficient. A team already using a mature central policy service may prefer to
keep that decision engine and implement the `PolicyEngine` interface, subject to
the revision contract required for approvals.

OPA and Cedar are established general-purpose policy systems. For example,
[Cedar documents default denial and forbid-overrides-permit](https://docs.cedarpolicy.com/auth/authorization.html).
AgentGuard's intended distinction is the Java tool-execution integration and the
combination of request-bound approvals and audit lifecycle, rather than a claim
that role checks or deny precedence are new.

## How it can contribute as agents become more capable

As applications expose more consequential tools, they need reviewable contracts
between a proposed operation and an authorized execution. AgentGuard's interfaces
give teams a place to implement that contract consistently across tools and
services, with tests that exercise failures as well as successful calls.

The implemented modules provide a base for these **future directions**, which
are not current guarantees:

- Shared transactional approval-store implementations and administrative review
  interfaces, with tenant isolation, retention and operational controls.
- External policy-engine adapters and safe policy rollout/version management.
- OpenTelemetry exporters and integrations with existing audit retention systems.
- Verified token/identity-provider integrations that preserve delegation and
  revocation semantics across services.
- Broader framework/version compatibility, distributed execution scenarios and
  independent security review.

There is no built-in risk-scoring model, prompt-injection detector, universal
agent sandbox, or cross-language runtime. Preventing an unauthorized tool action
does not prevent every malicious action an already authorized tool could perform.

## Try the evidence

- [H2 browser app](agentguard-examples/h2-orders-app/README.md): published release,
  real SQL, multiple users, approval queue and sanitized audit inspection.
- [Spring AI/MCP app](agentguard-examples/spring-ai-mcp-server/README.md): development
  modules, authenticated Streamable HTTP, real tool calls and reusable approvals.
- [Policy scenarios](specification/examples/policy-scenarios.json): runnable
  expected decisions, including an unprivileged caller denied approval eligibility.
- [Benchmarks](benchmarks/README.md): reproducible JMH workload and reporting
  instructions; performance results are workload-specific, not a security proof.
- [Security policy](SECURITY.md): enforcement boundaries and private reporting.

The standard for this project is small, explicit guarantees backed by executable
tests. Its usefulness should be judged by how reliably it enforces those contracts
in a real application's trusted execution path.
