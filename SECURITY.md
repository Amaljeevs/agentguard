# Security Policy

## Reporting Security Vulnerabilities

The AgentGuard project treats security vulnerabilities with the highest priority. If you discover a potential vulnerability in AgentGuard, please report it privately rather than opening a public GitHub issue.

### Reporting Process

1. Email your report to: [amaljeevs3739@gmail.com](mailto:amaljeevs3739@gmail.com) (or report via private GitHub Security Advisory).
2. Include the following details:
   - Component / module affected (`agentguard-core`, `agentguard-policy`, `agentguard-spring`, etc.)
   - Detailed description of the vulnerability and attack vector
   - Steps to reproduce or proof-of-concept code
   - Assessment of impact (e.g., authorization bypass, privilege escalation, denial of service)
3. You will receive an initial response confirming receipt within **24 hours**.
4. We will coordinate a patch, verify the fix with you, and schedule a coordinated public disclosure.

---

## Core Security Posture

AgentGuard is an authorization framework designed for zero-trust multi-agent environments. The codebase adheres strictly to the following guarantees:

1. **Deny by Default**:
   Any action, role, or resource not explicitly permitted by a validated policy will evaluate to `DENY`.
2. **Explicit Deny Precedence**:
   In any policy evaluation graph, a matching rule with effect `DENY` takes precedence over all matching `ALLOW` rules.
3. **Delegation Privilege Containment**:
   When an agent delegates an action to a secondary agent, the effective permissions are bounded by set intersection:
   $$\text{Permissions}_{\text{effective}} \subseteq \text{Permissions}_{\text{delegator}} \cap \text{Permissions}_{\text{delegate}}$$
   Privilege escalation through delegation chains is mathematically rejected.
4. **Fail-Closed Policy Bootstrapping**:
   If an application starts with an invalid, unreadable, or syntactically corrupt `agentguard-policy.yaml`, the Spring ApplicationContext immediately aborts initialization. It never falls back to an empty or permissive state.
5. **No Secrets in Audit Logs**:
   The audit engine enforces argument sanitization and field masking (`password`, `token`, `secret`, `apiKey`, `authorization`).
6. **No Prompt-Based Security Logic**:
   Authorization decisions are strictly deterministic and external to LLMs. AgentGuard never uses prompt-based classification for security decisions.

---

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.1.x` | :white_check_mark: Active Security Support |
| `< 0.1.0` | :x: Unsupported pre-release |
