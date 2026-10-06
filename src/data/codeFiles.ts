export interface CodeFile {
  name: string;
  path: string;
  module: string;
  language: string;
  description: string;
  content: string;
}

export const CODE_FILES: CodeFile[] = [
  {
    name: 'AgentIdentity.java',
    path: 'agentguard-core/src/main/java/io/agentguard/core/model/AgentIdentity.java',
    module: 'agentguard-core',
    language: 'java',
    description: 'Language-neutral security principal record representing an AI agent with validity interval and delegation lineage.',
    content: `package io.agentguard.core.model;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Language-neutral security principal representing an AI agent.
 * Holds verified identification, assigned roles, explicit permissions, delegation provenance,
 * and temporal validity boundaries.
 */
public record AgentIdentity(
    String agentId,
    AgentType agentType,
    Set<String> roles,
    Set<String> permissions,
    Optional<String> delegatedBy,
    Optional<String> sessionId,
    Instant issuedAt,
    Instant expiresAt,
    Map<String, Object> attributes
) {
    public AgentIdentity {
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(agentType, "agentType must not be null");
        Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");

        if (expiresAt.isBefore(issuedAt)) {
            throw new IllegalArgumentException("expiresAt cannot be earlier than issuedAt");
        }

        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        delegatedBy = delegatedBy == null ? Optional.empty() : delegatedBy;
        sessionId = sessionId == null ? Optional.empty() : sessionId;
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    public boolean isExpired(Instant now) {
        Objects.requireNonNull(now, "Reference instant must not be null");
        return now.isAfter(expiresAt);
    }

    public static Builder builder() {
        return new Builder();
    }
}`
  },
  {
    name: 'DefaultPolicyEngine.java',
    path: 'agentguard-core/src/main/java/io/agentguard/core/engine/DefaultPolicyEngine.java',
    module: 'agentguard-core',
    language: 'java',
    description: 'Stateless, deterministic Policy Decision Point (PDP) enforcing fail-closed checks, explicit deny precedence, and RBAC wildcards.',
    content: `package io.agentguard.core.engine;

import io.agentguard.core.model.*;
import java.time.Instant;
import java.util.*;

public class DefaultPolicyEngine implements PolicyEngine {

    private final PolicySet policySet;
    private final PermissionMatcher permissionMatcher;

    public DefaultPolicyEngine(PolicySet policySet) {
        this(policySet, new DefaultPermissionMatcher());
    }

    public DefaultPolicyEngine(PolicySet policySet, PermissionMatcher permissionMatcher) {
        this.policySet = Objects.requireNonNull(policySet);
        this.permissionMatcher = Objects.requireNonNull(permissionMatcher);
    }

    @Override
    public AuthorizationDecision evaluate(AuthorizationRequest request) {
        AgentIdentity subject = request.subject();
        Action action = request.action();
        Resource resource = request.resource();
        AuthorizationContext context = request.context();

        // 1. Identity validity & temporal check
        if (subject == null) {
            return AuthorizationDecision.deny("Denied: Subject agent identity is missing");
        }
        Instant evalTime = context.timestamp() != null ? context.timestamp() : Instant.now();
        if (subject.isExpired(evalTime)) {
            return AuthorizationDecision.deny(
                String.format("Denied: Agent identity '%s' expired at %s", subject.agentId(), subject.expiresAt())
            );
        }

        // 2. Explicit DENY rules (Deny takes precedence)
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.DENY && matchesRule(rule, subject, action, resource, context)) {
                return AuthorizationDecision.deny(rule.description().orElse("Denied by explicit rule"), policySet.name(), rule.id());
            }
        }

        // 3. APPROVAL_REQUIRED rules
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.APPROVAL_REQUIRED && matchesRule(rule, subject, action, resource, context)) {
                return AuthorizationDecision.requireApproval(rule.description().orElse("Action requires approval"), policySet.name(), rule.id());
            }
        }

        // 4. Explicit ALLOW rules
        for (PolicyRule rule : policySet.rules()) {
            if (rule.effect() == RuleEffect.ALLOW && matchesRule(rule, subject, action, resource, context)) {
                return AuthorizationDecision.allow(rule.description().orElse("Permitted by rule"), policySet.name(), rule.id());
            }
        }

        // 5. Evaluate RBAC Permissions with wildcards
        Set<String> effectivePermissions = collectEffectivePermissions(subject);
        for (String grantedPattern : effectivePermissions) {
            if (permissionMatcher.matches(grantedPattern, action.name())) {
                return AuthorizationDecision.allow("Permitted by role permission pattern '" + grantedPattern + "'", policySet.name());
            }
        }

        // 6. Deny by default
        return AuthorizationDecision.deny("Access denied: No matching permission or policy rule permits action '" + action.name() + "'");
    }
}`
  },
  {
    name: 'DefaultPermissionMatcher.java',
    path: 'agentguard-core/src/main/java/io/agentguard/core/engine/DefaultPermissionMatcher.java',
    module: 'agentguard-core',
    language: 'java',
    description: 'Hierarchical permission matcher supporting exact, universal (*), prefix (database.*), and suffix (*.read) matches.',
    content: `package io.agentguard.core.engine;

import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

public class DefaultPermissionMatcher implements PermissionMatcher {

    private final ConcurrentHashMap<String, Pattern> compiledPatterns = new ConcurrentHashMap<>();

    @Override
    public boolean matches(String pattern, String action) {
        if (pattern == null || action == null) return false;
        pattern = pattern.trim();
        action = action.trim();
        if (pattern.isEmpty() || action.isEmpty()) return false;

        // Universal wildcard
        if ("*".equals(pattern)) return true;

        // Exact match
        if (pattern.equals(action)) return true;

        // Hierarchical pattern matching
        if (pattern.contains("*")) {
            Pattern regex = compiledPatterns.computeIfAbsent(pattern, this::compilePattern);
            return regex.matcher(action).matches();
        }
        return false;
    }

    private Pattern compilePattern(String wildcardPattern) {
        StringBuilder regex = new StringBuilder("^");
        String[] parts = wildcardPattern.split("\\\\*", -1);
        for (int i = 0; i < parts.length; i++) {
            if (!parts[i].isEmpty()) {
                regex.append(Pattern.quote(parts[i]));
            }
            if (i < parts.length - 1) {
                regex.append(".*");
            }
        }
        regex.append("$");
        return Pattern.compile(regex.toString());
    }
}`
  },
  {
    name: 'DefaultPolicyEngineTest.java',
    path: 'agentguard-core/src/test/java/io/agentguard/core/engine/DefaultPolicyEngineTest.java',
    module: 'agentguard-core',
    language: 'java',
    description: 'Comprehensive JUnit 5 security test suite verifying allow, explicit deny precedence, approval required, and fail-closed behaviors.',
    content: `@DisplayName("DefaultPolicyEngine Security Matrix Tests")
class DefaultPolicyEngineTest {

    @Test
    @DisplayName("ALLOW: Developer agent querying database in development")
    void developerAccessInDev_shouldBeAllowed() { ... }

    @Test
    @DisplayName("DENY: Developer agent querying database in production (Explicit DENY overrides role allow)")
    void developerAccessInProd_shouldBeDeniedByRule() { ... }

    @Test
    @DisplayName("DENY: Expired agent identity must fail closed")
    void expiredIdentity_shouldFailClosed() { ... }

    @Test
    @DisplayName("APPROVAL_REQUIRED: DevOps deploying to production triggers human approval")
    void prodDeploy_shouldRequireApproval() { ... }

    @Test
    @DisplayName("ALLOW: Universal wildcard (*) permits all actions")
    void adminUniversalWildcard_shouldAllow() { ... }
}`
  },
  {
    name: 'YamlPolicyLoader.java',
    path: 'agentguard-policy/src/main/java/io/agentguard/policy/loader/YamlPolicyLoader.java',
    module: 'agentguard-policy',
    language: 'java',
    description: 'YAML policy loader and compiler with fail-closed schema validation converting YAML into immutable PolicySet graphs.',
    content: `package io.agentguard.policy.loader;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.agentguard.core.exception.InvalidPolicyException;
import io.agentguard.core.model.*;
import io.agentguard.policy.dto.*;
import java.io.*;
import java.util.*;

public class YamlPolicyLoader implements PolicyLoader {

    private final ObjectMapper yamlMapper;

    public YamlPolicyLoader() {
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
    }

    @Override
    public PolicySet load(InputStream inputStream) throws InvalidPolicyException {
        try {
            PolicyDocumentDto dto = yamlMapper.readValue(inputStream, PolicyDocumentDto.class);
            return compile(dto);
        } catch (JsonProcessingException e) {
            throw new InvalidPolicyException("Failed to parse YAML policy syntax: " + e.getOriginalMessage(), e);
        } catch (IOException e) {
            throw new InvalidPolicyException("I/O error reading policy: " + e.getMessage(), e);
        }
    }

    public PolicySet compile(PolicyDocumentDto dto) throws InvalidPolicyException {
        if (dto.version() == null || (!dto.version().equals("1") && !dto.version().equals("1.0"))) {
            throw new InvalidPolicyException("Unsupported policy version: " + dto.version());
        }
        if (dto.roles() == null || dto.roles().isEmpty()) {
            throw new InvalidPolicyException("Policy validation error: 'roles' section must not be empty");
        }

        // Map roles and rules into immutable PolicySet graph
        ...
    }
}`
  },
  {
    name: 'PolicyDocumentDto.java',
    path: 'agentguard-policy/src/main/java/io/agentguard/policy/dto/PolicyDocumentDto.java',
    module: 'agentguard-policy',
    language: 'java',
    description: 'Jackson YAML DTO record mapping version, metadata, roles, and fine-grained rule targets.',
    content: `package io.agentguard.policy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = false)
public record PolicyDocumentDto(
    @JsonProperty(value = "version", required = true)
    String version,

    @JsonProperty("metadata")
    Map<String, Object> metadata,

    @JsonProperty(value = "roles", required = true)
    Map<String, RoleDto> roles,

    @JsonProperty("rules")
    List<RuleDto> rules
) {}`
  },
  {
    name: 'YamlPolicyLoaderTest.java',
    path: 'agentguard-policy/src/test/java/io/agentguard/policy/loader/YamlPolicyLoaderTest.java',
    module: 'agentguard-policy',
    language: 'java',
    description: 'JUnit 5 test suite verifying valid YAML loading, schema error rejection, and fail-closed syntax error behavior.',
    content: `@DisplayName("YamlPolicyLoader Schema & Parsing Tests")
class YamlPolicyLoaderTest {

    @Test
    @DisplayName("Should load and compile valid YAML policy successfully")
    void shouldLoadValidYaml() {
        PolicySet policySet = loader.load(VALID_YAML);
        assertThat(policySet.name()).isEqualTo("enterprise-mcp-governance");
        assertThat(policySet.roles()).containsKeys("developer", "devops");
    }

    @Test
    @DisplayName("Should reject unsupported version and fail closed")
    void shouldRejectUnsupportedVersion() {
        assertThatThrownBy(() -> loader.load(badVersionYaml))
            .isInstanceOf(InvalidPolicyException.class);
    }
}`
  },
  {
    name: 'AuditEvent.java',
    path: 'agentguard-audit/src/main/java/io/agentguard/audit/model/AuditEvent.java',
    module: 'agentguard-audit',
    language: 'java',
    description: 'Immutable audit record holding principal, action, sanitized parameters, decision, and evaluation provenance.',
    content: `package io.agentguard.audit.model;

import io.agentguard.audit.sanitizer.*;
import io.agentguard.core.model.*;
import java.time.Instant;
import java.util.*;

public record AuditEvent(
    String eventId,
    Instant timestamp,
    String agentId,
    AgentType agentType,
    Set<String> roles,
    String action,
    Map<String, Object> parameters,
    String resourceType,
    String resourceId,
    String environment,
    Decision decision,
    String reason,
    Optional<String> matchedPolicyName,
    Optional<String> matchedRuleId,
    Optional<String> delegatedBy,
    Optional<String> sessionId,
    Map<String, Object> metadata
) {
    public static AuditEvent from(
        AuthorizationRequest request,
        AuthorizationDecision decision,
        ParameterSanitizer sanitizer
    ) {
        ...
    }
}`
  },
  {
    name: 'DefaultParameterSanitizer.java',
    path: 'agentguard-audit/src/main/java/io/agentguard/audit/sanitizer/DefaultParameterSanitizer.java',
    module: 'agentguard-audit',
    language: 'java',
    description: 'Recursive parameter sanitizer masking sensitive keys (passwords, tokens, api keys) in nested maps and lists.',
    content: `package io.agentguard.audit.sanitizer;

import java.util.*;

public class DefaultParameterSanitizer implements ParameterSanitizer {

    public static final String DEFAULT_MASK = "[REDACTED]";
    public static final Set<String> DEFAULT_SENSITIVE_KEYS = Set.of(
        "password", "secret", "token", "apikey", "key", "authorization", "credentials"
    );

    @Override
    public Map<String, Object> sanitize(Map<String, Object> parameters) {
        // Recursively traverses maps and lists, replacing sensitive values with [REDACTED]
        ...
    }
}`
  },
  {
    name: 'Slf4jAuditEventPublisher.java',
    path: 'agentguard-audit/src/main/java/io/agentguard/audit/publisher/Slf4jAuditEventPublisher.java',
    module: 'agentguard-audit',
    language: 'java',
    description: 'SLF4J audit publisher outputting structured, searchable log records with WARN for denials and INFO for allowances.',
    content: `package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;
import io.agentguard.core.model.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Slf4jAuditEventPublisher implements AuditEventPublisher {

    private static final Logger AUDIT_LOG = LoggerFactory.getLogger("io.agentguard.audit");

    @Override
    public void publish(AuditEvent event) {
        String logMessage = String.format(
            "[AgentGuard-Audit] id=%s decision=%s agentId=%s action=%s resource=%s:%s env=%s reason=\\"%s\\"",
            event.eventId(), event.decision(), event.agentId(), event.action(),
            event.resourceType(), event.resourceId(), event.environment(), event.reason()
        );

        if (event.decision() == Decision.DENY || event.decision() == Decision.APPROVAL_REQUIRED) {
            logger.warn(logMessage);
        } else {
            logger.info(logMessage);
        }
    }
}`
  },
  {
    name: 'AgentAuthorize.java',
    path: 'agentguard-spring/src/main/java/io/agentguard/spring/annotation/AgentAuthorize.java',
    module: 'agentguard-spring',
    language: 'java',
    description: 'Method and class-level declarative authorization annotation supporting SpEL expressions for resource and environment.',
    content: `package io.agentguard.spring.annotation;

import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AgentAuthorize {
    String value() default "";
    String action() default "";
    String resourceType() default "";
    String resourceId() default "";
    String environment() default "";
}`
  },
  {
    name: 'AgentAuthorizationAspect.java',
    path: 'agentguard-spring/src/main/java/io/agentguard/spring/aop/AgentAuthorizationAspect.java',
    module: 'agentguard-spring',
    language: 'java',
    description: 'Spring AOP Aspect intercepting @AgentAuthorize, evaluating SpEL, invoking PolicyEngine PDP, and publishing audit logs.',
    content: `package io.agentguard.spring.aop;

import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.*;
import io.agentguard.spring.annotation.AgentAuthorize;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

@Aspect
public class AgentAuthorizationAspect {
    @Around("@annotation(agentAuthorize)")
    public Object authorizeMethod(ProceedingJoinPoint joinPoint, AgentAuthorize agentAuthorize) throws Throwable {
        // 1. Resolve AgentIdentity from context
        // 2. Extract action and evaluate SpEL (#dbName, etc.)
        // 3. Delegate to PolicyEngine.evaluate(request)
        // 4. Publish AuditEvent
        // 5. Throw AgentAccessDeniedException / AgentApprovalRequiredException or proceed()
        ...
    }
}`
  },
  {
    name: 'McpAuthorizationExceptionMapper.java',
    path: 'agentguard-mcp/src/main/java/io/agentguard/mcp/error/McpAuthorizationExceptionMapper.java',
    module: 'agentguard-mcp',
    language: 'java',
    description: 'Translates AgentGuard exceptions into standard Model Context Protocol (MCP) JSON-RPC 2.0 error codes (-32003, -32004, -32001).',
    content: `package io.agentguard.mcp.error;

public final class McpAuthorizationExceptionMapper {
    public static McpErrorResponse toMcpError(Throwable throwable) {
        if (throwable instanceof AgentAccessDeniedException e) {
            return McpErrorResponse.of(McpErrorCode.ACCESS_DENIED, e.getMessage(), ...);
        }
        if (throwable instanceof AgentApprovalRequiredException e) {
            return McpErrorResponse.of(McpErrorCode.APPROVAL_REQUIRED, e.getMessage(), ...);
        }
        ...
    }
}`
  },
  {
    name: 'AgentGuardAutoConfiguration.java',
    path: 'agentguard-spring-boot-starter/src/main/java/io/agentguard/spring/boot/autoconfigure/AgentGuardAutoConfiguration.java',
    module: 'agentguard-starter',
    language: 'java',
    description: 'Spring Boot 3 auto-configuration registering PolicyLoader, PolicySet, PolicyEngine, and AgentAuthorizationAspect beans.',
    content: `package io.agentguard.spring.boot.autoconfigure;

@AutoConfiguration
@EnableConfigurationProperties(AgentGuardProperties.class)
@ConditionalOnProperty(prefix = "agentguard", name = "enabled", havingValue = "true", matchIfMissing = true)
public class AgentGuardAutoConfiguration {
    @Bean
    public PolicySet agentGuardPolicySet(...) { ... }

    @Bean
    public PolicyEngine agentGuardPolicyEngine(...) { ... }

    @Bean
    public AgentAuthorizationAspect agentAuthorizationAspect(...) { ... }
}`
  },
  {
    name: 'DatabaseTools.java',
    path: 'agentguard-examples/spring-mcp-example/src/main/java/io/agentguard/example/tools/DatabaseTools.java',
    module: 'spring-mcp-example',
    language: 'java',
    description: 'Example MCP tool service protected with @AgentAuthorize and SpEL expressions for environment and resource targeting.',
    content: `package io.agentguard.example.tools;

import io.agentguard.spring.annotation.AgentAuthorize;
import org.springframework.stereotype.Service;
import java.util.*;

@Service
public class DatabaseTools {

    @AgentAuthorize(
        action = "database.query",
        resourceType = "database",
        resourceId = "#databaseName",
        environment = "#environment"
    )
    public List<Map<String, Object>> queryDatabase(String databaseName, String sql, String environment) {
        return List.of(Map.of("id", 1, "db", databaseName));
    }

    @AgentAuthorize(
        action = "database.drop",
        resourceType = "database",
        resourceId = "#databaseName",
        environment = "#environment"
    )
    public String dropTable(String databaseName, String tableName, String environment) {
        return "Dropped table: " + tableName;
    }
}`
  },
  {
    name: 'SpringMcpExampleApplicationTest.java',
    path: 'agentguard-examples/spring-mcp-example/src/test/java/io/agentguard/example/SpringMcpExampleApplicationTest.java',
    module: 'spring-mcp-example',
    language: 'java',
    description: 'End-to-end integration test validating ALLOW, DENY, and APPROVAL_REQUIRED through full Spring Boot context.',
    content: `@SpringBootTest
@DisplayName("SpringMcpExampleApplication End-to-End Governance Tests")
class SpringMcpExampleApplicationTest {

    @Autowired private DatabaseTools databaseTools;
    @Autowired private KubernetesTools kubernetesTools;

    @Test
    void developerInDev_shouldBeAllowed() {
        authenticateAs("coding-agent-17", "DEVELOPER");
        var res = databaseTools.queryDatabase("cust-dev-db", "SELECT 1;", "development");
        assertThat(res).isNotEmpty();
    }

    @Test
    void developerInProd_shouldBeDenied() {
        authenticateAs("coding-agent-17", "DEVELOPER");
        assertThatThrownBy(() -> databaseTools.queryDatabase("cust-prod-db", "SELECT 1;", "production"))
            .isInstanceOf(AgentAccessDeniedException.class)
            .hasMessageContaining("deny-dev-prod-db");
    }

    @Test
    void devopsDeployProd_shouldRequireApproval() {
        authenticateAs("devops-agent-01", "DEVOPS");
        assertThatThrownBy(() -> kubernetesTools.deployService("prod-cluster", "auth", "v1.0", "production"))
            .isInstanceOf(AgentApprovalRequiredException.class)
            .hasMessageContaining("prod-deploy-approval");
    }
}`
  },
  {
    name: 'GETTING_STARTED.md',
    path: 'specification/docs/GETTING_STARTED.md',
    module: 'specification',
    language: 'markdown',
    description: 'Complete step-by-step developer guide for adding AgentGuard dependency, configuring policy, and protecting MCP tools.',
    content: `# Getting Started with AgentGuard

## 1. Add Maven Dependency
<dependency>
    <groupId>io.github.amaljeevs</groupId>
    <artifactId>agentguard-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>

## 2. Define Policy (agentguard-policy.yaml)
roles:
  developer:
    permissions: ["git.read", "database.query"]

rules:
  - id: "deny-dev-prod-db"
    effect: DENY
    target:
      roles: ["developer"]
      actions: ["database.query"]
      conditions:
        environment:
          equals: "production"

## 3. Protect Tools
@McpTool(name = "queryDatabase")
@AgentAuthorize("database.query")
public QueryResult queryDatabase(String query) { ... }`
  },
  {
    name: 'policy-schema.json',
    path: 'specification/policy-schema.json',
    module: 'specification',
    language: 'json',
    description: 'Language-neutral Draft-07 JSON Schema for validating agentguard-policy.yaml documents across all runtimes.',
    content: `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://agentguard.io/schemas/v1/policy.schema.json",
  "title": "AgentGuard Policy Schema",
  "type": "object",
  "required": ["version", "roles"],
  "properties": {
    "version": { "type": "string", "enum": ["1", "1.0"] },
    "roles": { "type": "object" },
    "rules": { "type": "array" }
  }
}`
  },
  {
    name: 'pom.xml',
    path: 'pom.xml',
    module: 'root',
    language: 'xml',
    description: 'Maven multi-module aggregator and build configuration for Java 21 with source/javadoc plugins.',
    content: `<project>
    <groupId>io.agentguard</groupId>
    <artifactId>agentguard-parent</artifactId>
    <version>0.1.0-SNAPSHOT</version>
    <packaging>pom</packaging>
    <modules>
        <module>agentguard-core</module>
        <module>agentguard-policy</module>
        <module>agentguard-audit</module>
        <module>agentguard-spring</module>
        <module>agentguard-spring-boot-starter</module>
        <module>agentguard-mcp</module>
    </modules>
</project>`
  }
];
