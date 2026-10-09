# AgentGuard Policy Specification

This document describes the declarative format implemented by the Java runtime.
The format can inform future ports; Python, TypeScript and Go runtimes are not
implemented. Semantics below describe 0.2.0-SNAPSHOT; 0.1.0 evaluates approval
rules before grants and does not enforce delegation ancestry.

---

## 1. Document Structure

A valid `agentguard-policy.yaml` has the following sections:
1. `version`: Mandatory string (`"1"` or `"1.0"`).
2. `metadata`: Optional name and description attributes.
3. `roles`: Map of role identifiers to permission lists.
4. `rules`: Ordered list of fine-grained contextual rules (ABAC, environment, approvals).

```yaml
version: "1.0"
metadata:
  name: "string"
  description: "string"

roles:
  <role_name>:
    description: "string"
    permissions:
      - "pattern"

rules:
  - id: "string"
    description: "string"
    effect: ALLOW | DENY | APPROVAL_REQUIRED
    target:
      roles: ["role1", "role2"]
      actions: ["action.pattern"]
      resources:
        type: "resource_type"
        id: "resource_id"
      conditions:
        environment:
          equals: "production"
          # or in: ["staging", "production"]
```

---

## 2. Permission Patterns & Wildcard Resolution

Permissions are hierarchical dot-separated strings evaluated by `PermissionMatcher`:

| Granted Pattern | Requested Action | Match Result | Explanation |
| :--- | :--- | :--- | :--- |
| `*` | `anything.nested.here` | **MATCH** | Universal wildcard matches all operations. |
| `database.query` | `database.query` | **MATCH** | Exact match. |
| `database.query` | `database.drop` | **NO MATCH** | Action mismatch. |
| `database.*` | `database.query` | **MATCH** | Prefix wildcard matches any child operation. |
| `database.*` | `database.schema.migrate` | **MATCH** | Prefix wildcard matches multi-level subpaths. |
| `*.read` | `logs.read` | **MATCH** | Suffix wildcard matches any resource read operation. |
| `*.read` | `git.read` | **MATCH** | Suffix wildcard. |
| `*.read` | `git.write` | **NO MATCH** | Operation does not end with `.read`. |

---

## 3. Evaluation Precedence & Semantics

For each identity in the request's verified delegation chain:

1. Require `issuedAt <= evaluationTime < expiresAt`.
2. Reject any matching explicit DENY rule.
3. Require a matching explicit ALLOW rule, role permission, or direct permission.
4. If an eligible action matches an APPROVAL_REQUIRED rule, require approval.
5. Otherwise allow the action.

No matching grant means DENY, even when an approval rule matches. Conditions in
one rule are combined: role membership, action pattern, resource type/id and
environment must all match when specified. Role and action target lists use any
matching member. Environment `equals` and `in` values are combined into a set.

The first matching rule of the relevant effect supplies the explanation. A
content fingerprint includes the ordered rules and sorted role permissions;
changing a policy invalidates approvals issued for its previous fingerprint.

## 4. Delegation

The application supplies AgentIdentityLookup backed by a trusted registry.
For the same action, resource and environment, every ancestor and the child
must have an underlying grant and no matching denial. Approval restrictions
from ancestors remain restrictions on the child. Unknown parents, lookup
failures, cycles, excessive depth and child validity outside parent validity
are denied. The default lookup resolves no parents, so delegated identities
are denied unless a trusted lookup is configured.

This is per-request intersection of authorization decisions. It does not compute
a static subset relation for arbitrary wildcard permission sets, authenticate
untrusted identities, or issue delegated credentials. The application owns those
identity lifecycle responsibilities.

## 5. Test policy behavior before deployment

From the repository root after `mvn install`:

```shell
mvn -f agentguard-policy/pom.xml org.codehaus.mojo:exec-maven-plugin:3.5.0:java "-Dexec.mainClass=io.agentguard.policy.testing.PolicyTestCli" "-Dexec.args=agentguard-examples/spring-ai-mcp-server/src/main/resources/agentguard-policy.yaml specification/examples/policy-scenarios.json"
```

Each scenario specifies a subject, action, resource, environment and expected
decision. The runner prints the decision explanation and matched rule and fails
when expectations do not match. The core engine accepts an explicit context
timestamp for deterministic evaluation; production callers must use trusted time.
