# AgentGuard Policy Specification

This document defines the language-neutral declarative policy format used by AgentGuard across Java, Python, TypeScript, and Go runtimes.

---

## 1. Document Structure

A valid `agentguard-policy.yaml` consists of three core sections:
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

The Policy Decision Point (PDP) enforces deterministic evaluation in the following strict order:

```text
[Incoming AuthorizationRequest]
              │
              ▼
    1. Identity Valid & Not Expired?
       ├── NO  ──► DENY (Fail closed)
       └── YES
              │
              ▼
    2. Any Explicit DENY Rule Matches?
       ├── YES ──► DENY (Explicit Deny Precedence)
       └── NO
              │
              ▼
    3. Any APPROVAL_REQUIRED Rule Matches?
       ├── YES ──► APPROVAL_REQUIRED (Requires Sign-off)
       └── NO
              │
              ▼
    4. Any Explicit ALLOW Rule Matches?
       ├── YES ──► ALLOW
       └── NO
              │
              ▼
    5. Any Role Permission Pattern Matches Action?
       ├── YES ──► ALLOW
       └── NO
              │
              ▼
    6. Deny-by-Default Fallback ──► DENY
```

---

## 4. Multi-Agent Delegation Invariant

When an agent delegates work to a sub-agent, AgentGuard mathematically guarantees that privileges cannot expand:

$$\text{Permissions}(\text{Sub-Agent}) \subseteq \text{Permissions}(\text{Parent Agent})$$

Privilege escalation through agent delegation chains is rejected at evaluation time.
