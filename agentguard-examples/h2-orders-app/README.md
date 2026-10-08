# AgentGuard H2 orders app

A runnable Spring Boot application using the **published AgentGuard 0.1.0**
dependencies, real prepared SQL statements, an embedded H2 database, Spring Security
login, a browser dashboard, and integration tests. No external database, Docker,
API key, or local AgentGuard build is required. This project is independent of the
repository's Maven reactor and can be copied elsewhere.

## Start the app

Requirements: JDK 21+ and Maven 3.6.3+. First build needs internet access for Maven
Central. The POM uses the Spring Boot 3.3.4 baseline of the published library.

From the repository root on Windows:

```powershell
cd agentguard-examples/h2-orders-app
.\run.ps1
```

The script selects `C:/Program Files/Java/jdk-21` when available, builds, tests,
and starts the app. For another installation, use `./run.ps1 -JavaHome 'your JDK path'`.
If PowerShell blocks local scripts, use the manual commands below.

On any platform, with Maven configured to use JDK 21+ (`mvn -version`):

```shell
cd agentguard-examples/h2-orders-app
mvn verify
java -jar target/h2-orders-app-1.0.0-SNAPSHOT.jar --debug=false
```

Open **http://localhost:8080** and sign in. Press Ctrl+C to stop. To choose a
different port, append `--server.port=8081` to the Java command.

| Username | Password | What to try |
| --- | --- | --- |
| developer | demo-pass | Read/create/refund development orders; production is explicitly denied |
| operator | demo-pass | Wildcard `orders.*` access; production refunds need approval; production deletion is denied |
| approver | demo-pass | Read orders and approve pending refunds; cannot create orders |
| auditor | demo-pass | Read development orders through a resource-specific ALLOW rule; inspect audits and previews |

These are local demo accounts. The app binds to loopback by default. H2 data,
approval requests, and audit history reset on each process restart. Both logical
databases (`orders-dev`, `orders-prod`) are seeded partitions in one H2 database.

## Walk through the app

1. Sign in as **developer** and load development orders. Seed IDs 1 and 3 are
   development orders; ID 2 is production.
2. Create an order using the supplied JSON. This executes an SQL INSERT. Open the
   latest `orders.create` audit entry: password, customer email, internal note,
   nested API key, and token inside a list are `[HIDDEN]`. Non-sensitive fields
   such as product and integration region remain visible.
   The terminal also prints these sanitized fields as a single-line JSON audit
   record under logger `io.agentguard.orders.audit.json`.
3. Select production and load orders: HTTP 403 with AgentGuard error `-32003`.
   The SQL query in the guarded service never executes.
4. Switch to **operator**, load production orders and click Refund: HTTP 202,
   error `-32004`, and a pending approval ID. The order stays PAID. Try Delete:
   the explicit deny wins over the operator's wildcard permission.
5. Switch to **approver**, refresh the queue, and approve the request. The SQL
   UPDATE marks the order REFUNDED. Repeated approval returns HTTP 409.
6. Inspect the audit trail and run core policy previews for identity expiration,
   direct permissions, delegation metadata, and default denial.

The dashboard uses session login and CSRF-protected requests. Refresh buttons
fetch current database state; this sample does not implement a streaming protocol.
All four roles can inspect this demo's audit and approval queues.

### Automated live API walkthrough

With the app running, open another PowerShell terminal in this directory:

```powershell
.\demo.ps1
# If running on another port:
.\demo.ps1 -BaseUrl http://localhost:8081
```

This authenticates real demo accounts, obtains CSRF tokens, creates and refunds
development/production orders, checks denied actions, approves a refund, verifies
replay rejection, and checks nested audit redaction. It creates new orders on each
run, so it can be repeated without restarting the server.

## Dependency features demonstrated

The single `io.github.amaljeevs:agentguard-spring-boot-starter:0.1.0` dependency
transitively includes all six modules. Web, Security and JDBC starters plus H2
provide the application infrastructure; no custom Maven repository is needed.

| Module | Working demonstration |
| --- | --- |
| `agentguard-core` | Policy engine, identity types, roles/direct permissions, wildcard matching, environment/resource conditions, DENY precedence, ALLOW rules, default denial, expiry, decision explanations, delegation/session metadata |
| `agentguard-policy` | Classpath YAML loading and compilation by the starter; policy rules in `agentguard-policy.yaml` |
| `agentguard-audit` | Recursive map/list sanitization, built-in key normalization, custom sensitive keys and mask, SQL publisher, SLF4J summary publisher, sanitized JSON console publisher, in-memory publisher, composite fan-out |
| `agentguard-spring` | `@AgentAuthorize`, AOP interception, SpEL resource/environment extraction, authenticated Spring Security principal to agent identity |
| `agentguard-spring-boot-starter` | Automatic policy engine/resolver/sanitizer configuration, configuration properties, custom audit publisher override |
| `agentguard-mcp` | Published exception mapper for access-denied and approval-required error objects in HTTP responses |

The core preview uses server-defined synthetic identities to demonstrate engine
features without executing SQL as those identities. Delegation metadata appears
in audit records; previews are clearly tagged with `metadata.preview=true`.

## Request flow and SQL

```text
Browser or API client
  -> Spring Security (authentication + CSRF)
  -> Controller resolves trusted resource/environment
  -> Spring proxy / @AgentAuthorize
     -> Identity resolver -> YAML policy engine
     -> Sanitized audit -> H2 + in-memory + SLF4J summary + JSON console log
     -> ALLOW: parameterized SQL executes
     -> DENY: HTTP 403, no business mutation
     -> APPROVAL_REQUIRED: queue request, HTTP 202, no refund yet
  -> Separate authenticated approver -> guarded refunds.approve -> SQL transaction
```

SQL statements use JDBC placeholders. User input is never treated as SQL syntax.
The production/development environment for refund/delete comes from the stored
order, not from a request parameter. Secrets submitted for the sanitizer demo
are never persisted in business tables. Customer email is business data stored
in the order table, but redacted from audit parameters.

The approval queue is **application code**, not a built-in library workflow.
`ApprovalService` authorizes the distinct `refunds.approve` action, prevents
self-approval, locks the approval row, and updates the order plus request in one
transaction. It does not bypass authorization or temporarily change the policy.

### How log sanitization works

The published starter supplies `ParameterSanitizer` from `agentguard-audit`.
The authorization aspect uses it when constructing `AuditEvent`, before the
event reaches any configured publisher. `AuditConfiguration` fans out the event
to SQL, memory, the library's decision-summary logger, and the example's
`SanitizedAuditLogPublisher`.

The JSON console publisher applies that same configured sanitizer to parameters
again at the log boundary, including for manually constructed events. It writes
only the sanitized parameters and selected decision metadata, using JSON escaping
and one physical line per event. Allowed decisions use INFO; blocked decisions
use WARN. Serialization failures emit a fixed message without raw input or
exception text.

For example, an input parameter map containing:

```json
{"password":"demo-secret","integration":{"api_key":"nested-secret","region":"local"}}
```

appears in the audit log's `parameters` field as:

```json
{"password":"[HIDDEN]","integration":{"api_key":"[HIDDEN]","region":"local"}}
```

Configure additional sensitive keys and the mask through `agentguard.audit` in
`application.yaml`. This sanitizes the structured audit log path; it is not a
global filter for arbitrary `log.info(...)` calls or third-party HTTP/SQL debug
logs. Do not log raw request bodies, authentication headers, or secret values.

## API

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/session` | Current user and CSRF header/token |
| GET | `/api/databases/{orders-dev or orders-prod}/orders` | Guarded SQL SELECT |
| POST | `/api/databases/{database}/orders` | Guarded SQL INSERT; JSON product/customerEmail/amount plus optional demo fields |
| POST | `/api/orders/{id}/refund` | Immediate development refund or production approval request |
| DELETE | `/api/orders/{id}` | Guarded SQL DELETE; production always denied |
| GET | `/api/approvals` | Current approval requests |
| POST | `/api/approvals/{id}/approve` | Approver-only atomic refund |
| GET | `/api/audit` | Latest 100 SQL audit events and publisher counts |
| POST | `/api/policy-preview` | Fixed core-engine scenarios and sanitized audit events |

API clients can use HTTP Basic. For mutations, first GET `/api/session`, retain
its session cookie, and send the returned CSRF token under its returned header
name. `demo.ps1` provides a complete implementation. Unauthenticated requests
receive 401; missing CSRF tokens receive 403 before AgentGuard runs.

## Tests and implementation boundaries

`mvn verify` runs real Spring Security/AOP/H2 integration tests for credentials,
CSRF, role/resource/environment rules, SQL changes, blocked mutations, recursive
redaction, custom sensitive fields, SQL injection treated as literal input,
approval workflow and replay protection, expiry and delegation audit metadata.
`AuditLogTest` captures emitted log messages and checks redaction for allowed and
denied requests, manually published events, newline escaping, and serialization
failure handling.

Version 0.1.0's sanitizer traverses maps/lists and matches sensitive key names;
it does not inspect arbitrary DTO fields or scrub secrets embedded in free-form
strings. The API deliberately passes structured maps and rejects null payload
values, which this version's immutable map/list copies cannot handle. Keep
secrets under sensitive keys rather than placing them in product descriptions.

Audit events represent **authorization decisions**, emitted before business SQL;
ALLOW does not prove a successful mutation. The published composite publisher
continues after a sink fails; this sample logs SQL audit failures. The in-memory
publisher and H2 tables retain events until restart and are intended for a local
demo, not long-running production retention.

This is an HTTP app using AgentGuard's MCP error mapper, not an MCP transport
server. The release does not implement approval orchestration, parent/child
permission-bound enforcement, risk scoring, OpenTelemetry/SIEM publishers, or
health endpoints. The example does not claim those as library capabilities.

Source entry points: `SecurityConfiguration`, `OrderService`, `ApprovalService`,
`AuditConfiguration`, `SanitizedAuditLogPublisher`, `InspectionService`, and `OrdersAppTest`. No local library
source changes or unpublished APIs are required.
