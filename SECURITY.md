# Security Policy

## Reporting vulnerabilities

Report privately to [amaljeevs3739@gmail.com](mailto:amaljeevs3739@gmail.com)
or use a private GitHub Security Advisory. Include the affected module/version,
impact, reproduction steps, and a minimal proof of concept where possible.
Do not include live credentials or sensitive customer data in the report.
We will coordinate investigation, fixes, and disclosure with the reporter.

## Release status

| Version | Status |
| --- | --- |
| 0.2.0 | Unreleased development code; contains the hardening described below |
| 0.1.0 | Published initial release; does not include the new hardening or approval/Spring AI modules |
| Older versions | Unsupported pre-release builds |

See [CHANGELOG.md](CHANGELOG.md) for version-specific changes. No independent
security audit or universal non-bypassability guarantee is claimed.

## Trust boundary

Authenticate callers before constructing AgentIdentity. Identity roles,
permissions, delegation parents, resource environments and policy files must come
from trusted application sources, not model output or unverified request fields.
The core evaluator consumes a trusted evaluation timestamp; production callers
must not let clients choose that clock. Spring Security remains responsible for
credentials, session/token validity, CSRF, and endpoint authorization.

Protect every business execution path. Spring AOP only intercepts calls through
its proxies; self-invocation, unproxied instances and separately exposed raw tool
callbacks can bypass that integration. Register only guarded Spring AI callbacks.
The library is not an operating-system sandbox and cannot constrain arbitrary
code outside its guarded execution path.

## Development-version enforcement

- Deny by default when no explicit grant or matching permission exists.
- Explicit DENY takes precedence over grants and approval rules.
- Approval is a restriction on an otherwise permitted action; it is not a grant.
- Configured expressions resolving to errors, null or blank deny rather than
  falling back to development/default resource values.
- Identities must satisfy `issuedAt <= evaluationTime < expiresAt`.
- A delegated request is evaluated for each ancestor returned by a trusted
  AgentIdentityLookup. Unknown parents, lookup failures, cycles, depth greater
  than the supported chain limit and child validity outside parent validity deny.
  This is per-request intersection of effective authorization, not static wildcard
  permission-set containment or a distributed identity verification protocol.
- Missing or invalid policy files prevent default Spring policy initialization.

The published 0.1.0 only stores delegation lineage; it does not enforce the
ancestor checks. Its expression fallback and approval precedence also differ.

## Approval storage and execution

The development approval module binds tickets to identity/session, action,
arguments, resource, environment, expiry, and policy content revision. Separate
approvers need `agentguard.approval.approve`; self-approval is rejected. Execution
rechecks policy, verifies the binding and atomically consumes the ticket first.
Failed execution does not restore a consumed ticket.

The reference InMemoryApprovalStore is bounded and single-process. It is lost
on restart and requires explicit expired-entry cleanup. Implement atomic store
transitions in shared storage for clustered deployments. Application code owns
business transactions, idempotency, crash recovery and reconciliation; approval
consumption is not an exactly-once distributed transaction.

Use an immutable/version-consistent PolicyEngine instance during each approval
operation. Custom engines must expose a revision that changes whenever effective
policy changes. Resolve current trusted identities at each request rather than
replaying stale caller-created identity objects.

## Audit redaction and failure behavior

Sanitization is structured and key/annotation based. It covers maps, collections,
arrays, records and public bean getters with bounded traversal. Unknown objects,
cycles and excessive depth are masked. Standard audit-event construction sanitizes
parameters and context metadata; the JSON publisher sanitizes again before output.

It does not detect secrets embedded in arbitrary strings, intercept every logger,
redact database contents, or guarantee that all personal data is removed. Configure
sensitive keys for your domain, keep credentials out of free-form fields, and
configure third-party request/SQL logging separately. Manually constructing and
publishing raw AuditEvent records bypasses the standard construction sanitizer;
custom publishers must enforce their own input contract.

The starter's enforcement path defaults to FAIL_CLOSED for publisher failures;
BEST_EFFORT must be chosen explicitly. Custom composite publishers have their own
failure policy. An AUTHORIZATION event is a policy decision, not proof of a
committed side effect. EXECUTION_SUCCEEDED means the callback returned normally;
post-execution publication can fail after side effects. No durable delivery or
non-repudiation guarantee is provided by console/in-memory publishers.

## Example applications

Example accounts, passwords, in-memory databases and review endpoints are local
demonstrations, not production identity or retention systems. The H2 dashboard
keeps CSRF protection. The separate stateless MCP machine-client example excludes
CSRF for its authenticated JSON API and MCP endpoint; do not apply that exclusion
to a browser-session application.
