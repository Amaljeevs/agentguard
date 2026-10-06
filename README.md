# AgentGuard

**Open-Source Authorization and Governance for AI Agents & Model Context Protocol (MCP)**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Java Version](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3%2B-brightgreen.svg)](https://spring.io/projects/spring-boot)

AgentGuard is a language-neutral authorization and governance framework for AI agents interacting with MCP servers, tools, APIs, databases, and infrastructure.

```text
                    AI Agents
       Coding       DevOps       Support
       Agent        Agent         Agent
          │            │             │
          └────────────┼─────────────┘
                       │
                Authentication (OAuth / JWT)
                       │
                       ▼
              ┌─────────────────┐
              │   AgentGuard    │
              ├─────────────────┤
              │ Agent Identity  │
              │ RBAC / ABAC     │
              │ Policy Engine   │
              │ Delegation      │
              │ Risk Evaluation │
              │ Approval        │
              │ Audit Logging   │
              └────────┬────────┘
                       │
                       ▼
                    MCP Server
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
            Git     Database    K8s
```

---

## Why AgentGuard?

Existing protocols like OAuth and OIDC answer **who authenticated the connection**. However, autonomous agents present distinct security challenges:

- **Coarse Scopes**: An OAuth token with `tools:call` allows calling any tool, with no distinction between reading logs and dropping a production database.
- **Prompt Injection Vulnerability**: Relying on system prompts ("*never delete tables*") fails against prompt injection. Security decisions must be **external, deterministic, and non-bypassable**.
- **The Tri-State Decision Model**: Autonomous operations require more than binary `ALLOW` and `DENY`. Sensitive operations require **`APPROVAL_REQUIRED`** to pause autonomous execution and request human sign-off.
- **Delegation Invariants**: When an agent delegates tasks to a sub-agent, permissions must be strictly bounded:
  $$\text{Permissions}_{\text{delegate}} \subseteq \text{Permissions}_{\text{delegator}}$$

---

## Core Principles

- **Agent Identity as a First-Class Principal**: An agent is an autonomous entity with roles, temporal validity, and delegation lineage.
- **Deny by Default**: Any unmapped action or role fails closed.
- **Explicit Deny Precedence**: A matching `DENY` rule overrides all `ALLOW` grants.
- **Language-Neutral Policies**: Policies are declarative YAML/JSON files governed by JSON Schema.
- **Zero-Dependency Core**: `agentguard-core` is written in pure Java 21 without framework dependencies.

---

## Quick Start (Spring Boot & MCP)

### 1. Add Maven Dependency

```xml
<dependency>
    <groupId>io.github.amaljeevs</groupId>
    <artifactId>agentguard-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

### 2. Define `agentguard-policy.yaml`

Place this in `src/main/resources/agentguard-policy.yaml`:

```yaml
version: "1.0"
metadata:
  name: "enterprise-mcp-governance"

roles:
  developer:
    permissions:
      - "git.read"
      - "git.write"
      - "logs.read"
      - "database.query"

  devops:
    permissions:
      - "logs.read"
      - "kubernetes.*"
      - "database.*"

rules:
  # Deny developers from querying production databases
  - id: "deny-dev-prod-db"
    effect: DENY
    target:
      roles: ["developer"]
      actions: ["database.query"]
      conditions:
        environment:
          equals: "production"

  # Production deployments require human approval
  - id: "prod-deploy-approval"
    effect: APPROVAL_REQUIRED
    target:
      actions: ["kubernetes.deploy"]
      conditions:
        environment:
          equals: "production"
```

### 3. Protect Tools with `@AgentAuthorize`

```java
@Service
public class DatabaseTools {

    @McpTool(name = "queryDatabase")
    @AgentAuthorize("database.query")
    public QueryResult queryDatabase(String query) {
        return dbClient.execute(query);
    }

    @McpTool(name = "deployCluster")
    @AgentAuthorize(action = "kubernetes.deploy", environment = "production")
    public Deployment deploy(String serviceName) {
        return k8sClient.deploy(serviceName);
    }
}
```

---

## Maven Module Architecture

| Module | Description |
| :--- | :--- |
| `agentguard-core` | Pure Java 21 domain models, records, and deterministic Policy Decision Point (PDP). Zero external dependencies. |
| `agentguard-policy` | YAML parser and JSON Schema validator for `agentguard-policy.yaml`. |
| `agentguard-audit` | Structured audit event publishers (SLF4J, OpenTelemetry, SIEM) with parameter sanitization. |
| `agentguard-spring` | `@AgentAuthorize` AOP interceptor and Spring Security context adapter. |
| `agentguard-spring-boot-starter`| Spring Boot 3 auto-configuration and health checks. |
| `agentguard-mcp` | MCP tool call filter, JSON-RPC error mapping (`-32003`, `-32004`). |
| `agentguard-examples` | Runnable Spring Boot MCP sample application. |
| `specification` | Language-neutral JSON Schema and architectural documentation. |

---

## Author & Maintainer

- **Author**: **Amal jeev s** ([@Amaljeevs](https://github.com/Amaljeevs))
- **Email**: `amaljeev3739@gmail.com`
- **Repository**: [https://github.com/Amaljeevs/agentguard](https://github.com/Amaljeevs/agentguard)

---

## Maven Central Publishing

Artifacts are published to Maven Central under group ID `io.github.amaljeevs`:

```xml
<dependency>
    <groupId>io.github.amaljeevs</groupId>
    <artifactId>agentguard-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

To release and publish to Maven Central via Sonatype Central Portal:

```bash
mvn clean deploy -P release
```

---

## License

AgentGuard is open source software licensed under the [Apache License, Version 2.0](LICENSE).
Copyright (c) 2026 Amal Jeev S.
