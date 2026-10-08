# Using the published AgentGuard dependency

This independent Java 21 / Spring Boot console application consumes
`io.github.amaljeevs:agentguard-spring-boot-starter:0.1.0` from Maven Central.
It has its own Spring Boot parent, is intentionally outside the root Maven reactor,
and can be copied to another directory and built without the AgentGuard source tree
or a preceding `mvn install`. Spring Boot 3.3.4 matches the library's release baseline.

## Run

Use JDK 21 or newer and Maven 3.6.3 or newer. Check `mvn -version` to ensure Maven
is using the correct JDK. From this directory:

```shell
mvn verify
java -jar target/published-dependency-example-1.0.0-SNAPSHOT.jar
```

Or run from the repository root:

```shell
mvn -f agentguard-examples/published-dependency-example/pom.xml verify
java -jar agentguard-examples/published-dependency-example/target/published-dependency-example-1.0.0-SNAPSHOT.jar
```

If Maven selects an older JDK on Windows, set these for the current PowerShell session
(adjust the installation path):

```powershell
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-21'
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
```

The program runs five simulated operations, prints their outcomes, and exits.
No database, Kubernetes cluster, credentials, or network service is required.

| Agent role | Operation | Environment | Expected result |
| --- | --- | --- | --- |
| developer | database.query | development | ALLOW |
| developer | database.query | production | DENY, error `-32003` |
| developer | kubernetes.deploy | development | DENY by default, error `-32003` |
| devops | kubernetes.deploy | production | APPROVAL_REQUIRED, error `-32004` |
| devops | kubernetes.deploy | development | ALLOW |

The final line is `Executed tool bodies: 2 (expected 2)`. The default SLF4J audit
publisher also logs evaluated decisions; the `password` parameter is redacted.

## How the integration works

1. `pom.xml` declares the released starter and Spring Boot runtime. It explicitly
   includes `spring-security-core`, which is optional in AgentGuard's Spring module
   but required by the default identity resolver. Maven Central is used by default;
   no custom repository or publishing credentials are needed.
2. `agentguard-policy.yaml` defines role permissions and environment-specific rules.
   The starter loads it and configures the policy engine, identity resolver,
   authorization aspect, parameter sanitizer, and audit publisher.
3. `DemoRunner` places a synthetic authenticated principal in Spring Security's
   context and calls a separate Spring-managed `GuardedTools` bean. In a real
   application, authentication must establish the principal and authorities through
   a trusted provider. Do not accept caller-supplied roles as authentication.
4. `@AgentAuthorize` extracts the resource and environment from method parameters
   using SpEL. Compiler parameter names are enabled in the POM. Calls must pass
   through the Spring proxy; self-invocation does not trigger the aspect.
5. The aspect evaluates the request, publishes an audit event, and executes the
   method only for ALLOW. The runner converts blocked-call exceptions with
   `McpAuthorizationExceptionMapper` from the published MCP module.

This demonstrates AgentGuard's MCP error mapping, not an MCP transport/server.
APPROVAL_REQUIRED blocks execution; the sample does not implement approval storage,
human sign-off, or automatic retries. Resource environments are hardcoded demo
inputs; a real application should derive them from trusted resource metadata.

The starter transitively supplies all six published modules:

| Module | Responsibility used by this example |
| --- | --- |
| agentguard-core | Identity, request and decision models; policy evaluation |
| agentguard-policy | YAML policy loading |
| agentguard-audit | Sanitized audit events and publishers |
| agentguard-spring | Annotation, AOP enforcement and Spring Security identity bridge |
| agentguard-spring-boot-starter | Automatic bean configuration |
| agentguard-mcp | Exception-to-error mapping |

The integration tests exercise the published starter, YAML loading, real AOP
interception, denied/approval calls not executing tool bodies, missing identity,
default denial, redacted audit parameters, and MCP error codes.

To inspect resolved modules:

```shell
mvn dependency:tree -Dincludes=io.github.amaljeevs
```

To prove resolution without artifacts previously installed in your normal Maven
cache, choose a new, empty cache directory:

```shell
mvn -Dmaven.repo.local=target/fresh-maven-cache verify
```

## Maven Central versus MvnRepository

Checked on October 7, 2026:

- [Maven Central's group directory](https://repo.maven.apache.org/maven2/io/github/amaljeevs/)
  lists the parent and all six library modules.
- [Starter release metadata](https://repo.maven.apache.org/maven2/io/github/amaljeevs/agentguard-spring-boot-starter/maven-metadata.xml)
  reports release `0.1.0`, with `lastUpdated` of `20261007123749`
  (October 7, 2026, 18:07:49 India time).
- [Sonatype's official FAQ](https://central.sonatype.org/faq/mvnrepository/)
  explains that MvnRepository is independent and Sonatype cannot guarantee its
  update frequency or accuracy. Maven does not depend on MvnRepository search.
- Automated access to MvnRepository search returned HTTP 403, so its current
  listing and exact reason for omission could not be independently confirmed.
  Given the fresh publication, a separate indexing delay is plausible, not proven.

Use the published coordinates directly. No re-release or POM change is needed
solely to appear in that third-party search. If the omission persists, contact
MvnRepository through its site with the coordinates and Maven Central artifact
link; only its operator can explain its indexing state.
