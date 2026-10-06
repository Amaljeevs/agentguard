# Getting Started with AgentGuard

This guide walks you through integrating **AgentGuard** into a Spring Boot application or Model Context Protocol (MCP) tool server.

---

## 1. Add Maven Dependency

Add the AgentGuard Spring Boot starter to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.amaljeevs</groupId>
    <artifactId>agentguard-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

---

## 2. Configure `application.yaml`

Enable AgentGuard and configure policy location and operational environment:

```yaml
agentguard:
  enabled: true
  policy-location: "classpath:agentguard-policy.yaml"
  environment: "development" # Default fallback environment
  audit:
    enabled: true
    mask-token: "[REDACTED]"
    sensitive-keys:
      - "password"
      - "token"
      - "secret"
      - "apiKey"
```

---

## 3. Define Declarative Policy (`agentguard-policy.yaml`)

Place `agentguard-policy.yaml` in `src/main/resources/`:

```yaml
version: "1.0"
metadata:
  name: "enterprise-mcp-governance"
  description: "Access policy for autonomous agents"

roles:
  developer:
    description: "Software engineering assistant"
    permissions:
      - "git.read"
      - "git.write"
      - "logs.read"
      - "database.query"

  devops:
    description: "Infrastructure management agent"
    permissions:
      - "logs.read"
      - "kubernetes.*"
      - "database.*"

  admin:
    description: "Universal administrative agent"
    permissions:
      - "*"

rules:
  # Deny developers from querying production databases
  - id: "deny-dev-prod-db"
    description: "Developers cannot access production databases"
    effect: DENY
    target:
      roles: ["developer"]
      actions: ["database.query"]
      resources:
        type: "database"
      conditions:
        environment:
          equals: "production"

  # Production deployments require human approval
  - id: "prod-deploy-approval"
    description: "Kubernetes production deployment requires approval"
    effect: APPROVAL_REQUIRED
    target:
      actions: ["kubernetes.deploy"]
      conditions:
        environment:
          equals: "production"

  # Prevent destructive operations across all agents in production
  - id: "deny-destructive-drop-prod"
    description: "Block drop commands in production"
    effect: DENY
    target:
      actions: ["database.drop", "database.truncate"]
      conditions:
        environment:
          equals: "production"
```

---

## 4. Protect Methods with `@AgentAuthorize`

Annotate any service method or MCP tool:

```java
@Service
public class CloudTools {

    // Simple action declaration
    @McpTool(name = "readLogs")
    @AgentAuthorize("logs.read")
    public List<String> readLogs(String service) {
        return logService.fetch(service);
    }

    // Dynamic SpEL argument resolution
    @McpTool(name = "queryDatabase")
    @AgentAuthorize(
        action = "database.query",
        resourceType = "database",
        resourceId = "#dbName",
        environment = "#env"
    )
    public List<Map<String, Object>> queryDatabase(String dbName, String sql, String env) {
        return dbClient.query(dbName, sql);
    }
}
```

---

## 5. Decision Outcomes & MCP Error Codes

When a method is called, AgentGuard intercepts the call and evaluates the active policy:

| Decision | Aspect Behavior | MCP JSON-RPC Translation |
| :--- | :--- | :--- |
| **`ALLOW`** | Proceed with target method execution. | Normal tool execution result returned. |
| **`DENY`** | Throws `AgentAccessDeniedException`. | Mapped to MCP error code `-32003` (`ACCESS_DENIED`). |
| **`APPROVAL_REQUIRED`** | Throws `AgentApprovalRequiredException`. | Mapped to MCP error code `-32004` (`APPROVAL_REQUIRED`). |
| **Unauthenticated / Expired** | Throws `AgentAuthenticationException`. | Mapped to MCP error code `-32001` (`AUTHENTICATION_FAILED`). |

---

## 6. Audit Logging

Every authorization decision automatically produces an immutable, sanitized `AuditEvent` logged to SLF4J under logger `io.agentguard.audit`.

Sensitive keys (`password`, `token`, `secret`, `apiKey`) are automatically masked:

```text
[AgentGuard-Audit] id=7b2e1a... decision=DENY agentId=coding-agent-17 action=database.query resource=database:cust-prod-db env=production reason="Developers cannot access production databases" rule=deny-dev-prod-db
```
