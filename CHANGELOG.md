# Changelog

## 1.0.0 (Planned Stable Release)

AgentGuard 1.0.0 represents the first major, production-stable release of AgentGuard. It finalizes the core API contracts, security invariants, enterprise identity mappings, and architectural guarantees for tool authorization, cryptographic request-bound approvals, and sanitized audit logging.

### Production Stability Guarantees
- **Finalized Core API Contract**: Stable, frozen public interfaces for `PolicyEngine`, `AgentIdentityResolver`, `ApprovalService`, `ApprovalStore`, and `AuditPublisher`.
- **Deterministic Governance Invariants**: Guaranteed fail-closed, deny-by-default evaluation across all paths; strict precedence (`DENY` > `APPROVAL_REQUIRED` > `ALLOW`); delegation authority monotonicity (`child permissions ⊆ parent permissions`), cycle detection, and bounded depth.
- **Cryptographic Request-Bound Approvals**: Deterministic SHA-256 canonical argument hashing (`ApprovalTicket`) preventing argument tampering (such as unauthorized payment amount alterations or IBAN redirection in financial flows), atomic single-use ticket consumption (`CONSUMED`), and durable multi-node concurrency protection with `PostgresApprovalStore` (`SELECT ... FOR UPDATE`).
- **Production Observability & Tracing**: Low-cardinality Micrometer metrics (`agentguard.decisions`, latency timers, approval counters) and OpenTelemetry-compatible `AgentGuardTracingHook` SPI for distributed trace ID propagation with zero secret leakage.
- **Enterprise Identity & Multi-Tenancy**: Verified claims mapping for JWTs (OAuth2/OIDC, Microsoft Entra ID, Keycloak), SPIFFE SVID workload identities, and tenant isolation.
- **Fintech & Multi-Channel Reference Architecture**: Complete Model Context Protocol (MCP) and multi-channel agent/chatbot connector (`/api/agent/channel/invoke`), demonstrated in `agentguard-examples/fintech-banking-mcp-server`.
- **Adversarial Security Test Suite**: Full test coverage of all 15 attack vectors including privilege escalation, replay attacks, race conditions, delegation cycles, and malformed inputs.

## 0.2.1 (Current Latest Release)

### Additions and Improvements
- **Durable Approval Store**: Added `PostgresApprovalStore` in `agentguard-approval` with `SELECT ... FOR UPDATE` row-level locking, atomic single-use ticket consumption (`CONSUMED`), index-optimized schema DDL (`schema-postgresql.sql`), and prevention of concurrent double-consumption.
- **Observability**: Added `AgentGuardMetrics` pluggable metrics SPI and `MicrometerAgentGuardMetrics` with strictly low-cardinality labels (`decision`, `risk`, `event`, `error_type`), policy evaluation duration timer, and secret redaction. Added OpenTelemetry-compatible `AgentGuardTracingHook` SPI for distributed trace ID propagation.
- **Language-Neutral REST API**: Added `agentguard-spring-web` auto-configuration (`AgentGuardWebAutoConfiguration`) exposing `POST /v1/authorize` with cross-language support (Python client example included).
- **Workload & Enterprise Identity**: Added `SpiffeAgentIdentityResolver` for SPIFFE workload SVID identity resolution (`spiffe://<trust-domain>/<workload>`). Added Microsoft Entra ID (`oid`, `azp`, `appid`, `tid`) and Keycloak (`resource_access`) claim mapping in `JwtClaimsAgentIdentityResolver`.
- **Security & Adversarial Suite**: Added comprehensive parameterized test suite covering all 15 attack vectors: privilege escalation, forged identities, delegation cycles, excessive delegation depth, expired delegation, child exceeding parent permissions, modified requests after approval, replay attacks, concurrent consumption race conditions, malformed JWT claims, malformed policies, expression evaluation errors, canonical argument hashing edge cases, wildcard permission matching, and fail-closed deny-by-default behavior.

## 0.2.0

### Security and behavior changes

- Configured authorization expressions that fail or resolve to null/blank now
  deny the call instead of falling back to development/default resources.
- Approval-required rules require an underlying role/identity permission or
  explicit ALLOW rule. Approval never creates permission.
- Delegated requests require an `AgentIdentityLookup` backed by trusted data.
  The child and every parent must authorize the request, the full claimed chain
  must match trusted lookup data, and child permissions must remain a subset of
  parent authority. Unknown parents, cycles, excessive depth, and child validity
  outside parent validity deny.
- Identity expiration is exclusive: an identity is expired at `expiresAt`.
  Identities cannot be used before `issuedAt`.
- Structured sanitization supports nulls, arrays, records, bean getters,
  `@Sensitive`, cycles and bounded traversal. Unsupported values are masked.
- Custom audit masks apply even without extra sensitive keys. Audit enablement
  and failure mode configuration are honored by the starter's enforcement path.

### Additions

- Reusable JSON audit publisher and execution lifecycle records with correlation
  IDs and content-based policy revisions. Default starter audit failure mode is
  FAIL_CLOSED. Composite publishers support explicit failure modes.
- `agentguard-approval`: request binding, expiration, separate approver permission,
  rejection, immutable execution snapshots and atomic single-use consumption.
- `agentguard-spring-ai`: guarded ToolCallback/ToolCallbackProvider adapters.
- Verified-claims identity mapping for JWT `sub`, `client_id`, `actor`/`act`,
  tenant, scopes, roles and delegation chain, with Spring Security JWT support.
- Policy IDs/versions/content hashes, risk and trace metadata on decisions;
  deterministic results when callers supply a fixed trusted timestamp and trace.
- Approval tickets expose action/resource/arguments hashes and lifecycle states
  `APPROVAL_REQUIRED`, `APPROVED`, `DENIED`, `EXPIRED` and `CONSUMED`.
- `agentguard-spring-web`: optional language-neutral `POST /v1/authorize` adapter.
- `AgentGuard.authorize(request)` facade and concise `resource` annotation alias.
- A real Streamable HTTP MCP/H2 example with authenticated identity propagation,
  reusable approvals, executable client walkthrough, and network integration tests.
- Declarative policy test CLI, JMH benchmark harness, consumer CI jobs, and
  `why-agentguard.md` with Spring Security positioning and roadmap boundaries.
- The starter brings its required Spring AOP and Spring Security core dependencies.

### Migration from 0.1.0

- Fix invalid SpEL expressions; use `#p0`/`#a0` aliases if parameter names are not retained.
- Add explicit permissions for actions subject to approval.
- Register a trusted delegation lookup, or stop supplying unverified `delegatedBy` values.
- Resolve identity from trusted authentication context. Do not deserialize roles,
  permissions or delegation authority from authorization request payloads.
- Expect AUTHORIZATION plus EXECUTION_SUCCEEDED/EXECUTION_FAILED audit records for
  allowed calls. Update event-count assertions and downstream audit consumers.
- Set `agentguard.audit.failure-mode=BEST_EFFORT` only if continuing without a
  successful audit write is acceptable. A post-execution publication failure can
  surface after a side effect; applications still need idempotency.

## 0.1.0

Initial Maven Central release: Java policy engine, YAML policy loader, audit
sanitization/publishers, Spring AOP, Boot auto-configuration, and MCP error mapping.
