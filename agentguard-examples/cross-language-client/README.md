# AgentGuard Cross-Language Client Example

AgentGuard provides deterministic authorization and governance not just for Java, but for any AI agent environment (Python, Node.js, Go, Rust) via its standard HTTP authorization endpoint (available in release 0.2.1 and stabilized for 1.0.0):

```http
POST /v1/authorize
```

## Security Invariants

1. **Authentication Complements Authorization**: The client supplies its verified transport credentials (e.g., Bearer JWT or mTLS SPIFFE SVID in HTTP headers). AgentGuard extracts identity securely server-side; untrusted fields in request payloads cannot elevate privileges.
2. **Deterministic Evaluation**: AgentGuard validates the action, resource, sanitized canonical arguments, and environment against declarative policies.
3. **Fail-Closed Governance**: Returns `ALLOW`, `DENY`, or `APPROVAL_REQUIRED`.

## Running the Example

```bash
# Set endpoint if different from default
export AGENTGUARD_ENDPOINT=http://localhost:8080/v1/authorize
export AUTH_TOKEN="Bearer your-jwt-token"

python3 authorize_client.py
```

## Response Schema

```json
{
  "decision": "ALLOW",
  "reason": "Permitted by rule prod-deploy",
  "matchedPolicyId": "cluster-governance",
  "matchedRuleId": "prod-deploy",
  "policyVersion": "1.0",
  "policyHash": "sha256-...",
  "riskLevel": "MEDIUM",
  "approvalRequestId": null,
  "traceId": "trace-uuid-123"
}
```

