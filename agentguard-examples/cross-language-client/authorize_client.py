#!/usr/bin/env python3
"""
AgentGuard Cross-Language Authorization Client (Python Example).

Demonstrates how any non-Java agent (Python, TypeScript, Go, etc.) integrates
with AgentGuard's language-neutral REST endpoint (POST /v1/authorize).

Security Invariants:
1. Identity is verified via standard transport tokens (e.g., Bearer JWT/SPIFFE).
2. The payload NEVER self-assigns authority or roles; all permissions are evaluated
   against server-side deterministic policies.
3. Handles all 3 governance outcomes: ALLOW, DENY, and APPROVAL_REQUIRED.
"""

import json
import os
import sys
import urllib.request
import urllib.error

AGENTGUARD_ENDPOINT = os.getenv("AGENTGUARD_ENDPOINT", "http://localhost:8080/v1/authorize")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "Bearer simulated-jwt-token-from-auth-service")


def authorize_action(action: str, resource_type: str, resource_id: str,
                     arguments: dict, environment: str = "production") -> dict:
    """
    Submits an authorization request to AgentGuard.

    :param action: Action name, e.g., 'kubernetes.deploy' or 'database.query'
    :param resource_type: Resource category, e.g., 'k8s_cluster' or 'postgres_db'
    :param resource_id: Specific resource identifier
    :param arguments: Action arguments (canonicalized and bound server-side)
    :param environment: Runtime context environment (e.g., 'production', 'staging')
    :return: Decision payload dictionary from AgentGuard
    """
    payload = {
        "action": action,
        "resource": {
            "type": resource_type,
            "id": resource_id,
            "tags": {"env": environment}
        },
        "arguments": arguments,
        "context": {
            "environment": environment
        }
    }

    req = urllib.request.Request(
        AGENTGUARD_ENDPOINT,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": AUTH_TOKEN,
            "User-Agent": "AgentGuard-Python-Client/0.2.1"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        try:
            return json.loads(error_body)
        except Exception:
            raise RuntimeError(f"HTTP {e.code}: {error_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed to {AGENTGUARD_ENDPOINT}: {e.reason}") from e


def handle_decision(decision: dict) -> None:
    """Evaluates the AgentGuard governance decision."""
    status = decision.get("decision")
    reason = decision.get("reason", "No reason provided")
    trace_id = decision.get("traceId")
    risk = decision.get("riskLevel", "UNKNOWN")

    print(f"Decision: {status} | Risk: {risk} | Trace: {trace_id}")

    if status == "ALLOW":
        print(f" -> Access Granted! Matched Policy: {decision.get('matchedPolicyId')}")
        print(" -> Safe to proceed with tool execution.")
    elif status == "DENY":
        print(f" -> Access DENIED: {reason}")
        print(f" -> Rule: {decision.get('matchedRuleId')}")
        print(" -> Halting execution. Security invariant preserved.")
    elif status == "APPROVAL_REQUIRED":
        approval_id = decision.get("approvalRequestId")
        print(f" -> Human Approval Required! Request ID: {approval_id}")
        print(f" -> Reason: {reason}")
        print(" -> Pausing agent workflow until authorized ticket is approved.")
    else:
        print(f" -> Unexpected decision status: {status}")


if __name__ == "__main__":
    print("=== AgentGuard Cross-Language Client Example ===")
    sample_request = {
        "action": "kubernetes.deploy",
        "resource_type": "k8s_cluster",
        "resource_id": "prod-cluster-us-east",
        "arguments": {
            "image": "ghcr.io/mycorp/payment-service:v2.1.0",
            "replicas": 3,
            "canary": False
        },
        "environment": "production"
    }
    print(f"Evaluating action '{sample_request['action']}' on '{sample_request['resource_id']}'...")
    try:
        result = authorize_action(**sample_request)
        handle_decision(result)
    except Exception as err:
        print(f"Client execution note: {err}")
        print("Note: Start an AgentGuard Spring Boot application with agentguard-spring-web to run against a live server.")

