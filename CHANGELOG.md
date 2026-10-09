# Changelog

## 0.2.0 — prepared for release; publication pending

### Security and behavior changes

- Configured authorization expressions that fail or resolve to null/blank now
  deny the call instead of falling back to development/default resources.
- Approval-required rules require an underlying role/identity permission or
  explicit ALLOW rule. Approval never creates permission.
- Delegated requests require an `AgentIdentityLookup` backed by trusted data.
  The child and every parent must authorize the request. Unknown parents,
  cycles, excessive depth, and child validity outside parent validity deny.
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
- A real Streamable HTTP MCP/H2 example with authenticated identity propagation,
  reusable approvals, executable client walkthrough, and network integration tests.
- Declarative policy test CLI, JMH benchmark harness, consumer CI jobs, and
  `why-agentguard.md` with Spring Security positioning and roadmap boundaries.
- The starter brings its required Spring AOP and Spring Security core dependencies.

### Migration from 0.1.0

- Fix invalid SpEL expressions; use `#p0`/`#a0` aliases if parameter names are not retained.
- Add explicit permissions for actions subject to approval.
- Register a trusted delegation lookup, or stop supplying unverified `delegatedBy` values.
- Expect AUTHORIZATION plus EXECUTION_SUCCEEDED/EXECUTION_FAILED audit records for
  allowed calls. Update event-count assertions and downstream audit consumers.
- Set `agentguard.audit.failure-mode=BEST_EFFORT` only if continuing without a
  successful audit write is acceptable. A post-execution publication failure can
  surface after a side effect; applications still need idempotency.
- Publication is pending. Build this version locally until it is available; the two
  published-dependency examples remain pinned to 0.1.0 and demonstrate that release.

## 0.1.0

Initial Maven Central release: Java policy engine, YAML policy loader, audit
sanitization/publishers, Spring AOP, Boot auto-configuration, and MCP error mapping.
