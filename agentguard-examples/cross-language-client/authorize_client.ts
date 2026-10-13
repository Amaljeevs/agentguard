/**
 * AgentGuard Cross-Language Authorization Client (TypeScript / Node.js Example).
 *
 * Demonstrates how any non-Java agent (TypeScript, Python, Go, Rust) integrates
 * with AgentGuard's language-neutral REST endpoint (POST /v1/authorize).
 *
 * Security Invariants:
 * 1. Identity is verified via standard transport tokens (e.g., Bearer JWT/SPIFFE).
 * 2. Untrusted models NEVER supply effective identity, roles, or permissions.
 * 3. Handles all 3 governance outcomes: ALLOW, DENY, and APPROVAL_REQUIRED.
 */

interface AuthorizationRequest {
  action: string;
  resource: {
    type: string;
    id: string;
    tags?: Record<string, string>;
  };
  arguments: Record<string, unknown>;
  context?: {
    environment?: string;
    metadata?: Record<string, string>;
  };
}

interface AuthorizationResponse {
  decision: "ALLOW" | "DENY" | "APPROVAL_REQUIRED";
  reason: string;
  matchedPolicyId?: string;
  matchedRuleId?: string;
  policyVersion?: string;
  policyHash?: string;
  riskLevel?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  approvalRequestId?: string | null;
  traceId?: string;
}

const AGENTGUARD_ENDPOINT = process.env.AGENTGUARD_ENDPOINT || "http://localhost:8080/v1/authorize";
const AUTH_TOKEN = process.env.AUTH_TOKEN || "Bearer simulated-jwt-token-from-auth-service";

export async function authorizeAction(request: AuthorizationRequest): Promise<AuthorizationResponse> {
  const response = await fetch(AGENTGUARD_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": AUTH_TOKEN,
      "User-Agent": "AgentGuard-TypeScript-Client/1.0.0"
    },
    body: JSON.stringify(request)
  });

  if (!response.ok && response.status !== 403) {
    const errorBody = await response.text();
    throw new Error(`AgentGuard HTTP ${response.status}: ${errorBody}`);
  }

  return (await response.json()) as AuthorizationResponse;
}

// Example usage
async function main() {
  const request: AuthorizationRequest = {
    action: "kubernetes.deploy",
    resource: {
      type: "cluster",
      id: "prod-cluster-us-east",
      tags: { env: "production" }
    },
    arguments: {
      image: "registry.internal/payments-service:v2.4.1",
      replicas: 3
    },
    context: {
      environment: "production"
    }
  };

  console.log("Submitting authorization request to AgentGuard...");
  const decision = await authorizeAction(request);

  console.log(`Decision: ${decision.decision} | Risk: ${decision.riskLevel} | Trace: ${decision.traceId}`);

  switch (decision.decision) {
    case "ALLOW":
      console.log("✓ Access granted. Proceeding with tool execution.");
      // Execute tool here
      break;
    case "DENY":
      console.error(`✗ Access denied: ${decision.reason} (Rule: ${decision.matchedRuleId})`);
      // Halt execution fail-closed
      break;
    case "APPROVAL_REQUIRED":
      console.warn(`! Human approval required. Request ID: ${decision.approvalRequestId}`);
      console.warn("  Workflow paused until approval ticket is signed.");
      break;
  }
}

if (require.main === module) {
  main().catch(console.error);
}

