# Getting started with AgentGuard

Choose the version you want to evaluate:

- **Published 0.1.0:** [H2 orders dashboard](../../agentguard-examples/h2-orders-app/README.md)
  or [standalone console demo](../../agentguard-examples/published-dependency-example/README.md).
  These resolve released Maven Central artifacts without building this repository.
- **Release 0.2.1:** [Spring AI/MCP server](../../agentguard-examples/spring-ai-mcp-server/README.md).
  Build the libraries locally with `mvn install`, then run the real MCP client
  walkthrough and the reusable approval workflow.

See the [root README](../../README.md) for starter configuration and annotation
examples, [policy specification](POLICY_SPECIFICATION.md) for evaluation semantics,
and [migration notes](../../CHANGELOG.md) for changed behavior.

Authentication is owned by Spring Security or your application's trusted identity
provider. AgentGuard does not supply OAuth token validation, an MCP transport,
or a review UI through its core starter. Its verified-claims adapter consumes
claims only after an upstream verifier validates signature, issuer and audience.
It provides authorization integration;
the new example explicitly configures the transport, authentication, and storage.

The annotation integration throws AgentAccessDeniedException for missing/invalid
identity and denied policy decisions. AgentApprovalRequiredException blocks
eligible operations requiring review. The MCP error mapper is an explicit utility,
not an automatic transport filter. The Spring AI MCP example instead returns MCP
tool-error results from its guarded callbacks.

Plain Java callers can use
`new AgentGuard(policyEngine, trustedIdentityResolver).authorize(request)`; the
facade replaces any request-carried identity with the verified current identity.
Non-Java clients can use the optional `agentguard-spring-web` module's
`POST /v1/authorize` adapter after the host application registers its trusted
identity resolver. Request payloads never grant roles or permissions.

For why these components complement Spring Security, read
[why-agentguard.md](../../why-agentguard.md).
