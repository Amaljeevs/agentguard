package io.agentguard.policy.loader;

import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.exception.InvalidPolicyException;
import io.agentguard.core.model.Action;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AuthorizationContext;
import io.agentguard.core.model.AuthorizationDecision;
import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.core.model.Decision;
import io.agentguard.core.model.PolicySet;
import io.agentguard.core.model.Resource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("YamlPolicyLoader Schema & Parsing Tests")
class YamlPolicyLoaderTest {

    private YamlPolicyLoader loader;

    @BeforeEach
    void setUp() {
        loader = new YamlPolicyLoader();
    }

    private static final String VALID_YAML = """
        version: "1.0"
        metadata:
          name: "enterprise-mcp-governance"
          description: "Core access policy for developer and devops agents"
        roles:
          developer:
            description: "Software engineering agent"
            permissions:
              - "git.read"
              - "git.write"
              - "database.query"
          devops:
            description: "DevOps automation agent"
            permissions:
              - "kubernetes.*"
              - "logs.read"
        rules:
          - id: "deny-dev-prod-db"
            description: "Developers cannot access production databases"
            effect: "DENY"
            target:
              roles:
                - "developer"
              actions:
                - "database.query"
              resources:
                type: "database"
              conditions:
                environment:
                  equals: "production"
          - id: "prod-deploy-approval"
            description: "Production deployments require human approval"
            effect: "APPROVAL_REQUIRED"
            target:
              actions:
                - "kubernetes.deploy"
              conditions:
                environment:
                  in:
                    - "production"
                    - "prod-dr"
        """;

    @Test
    @DisplayName("Should load and compile valid YAML policy successfully")
    void shouldLoadValidYaml() {
        PolicySet policySet = loader.load(VALID_YAML);

        assertThat(policySet).isNotNull();
        assertThat(policySet.name()).isEqualTo("enterprise-mcp-governance");
        assertThat(policySet.version()).isEqualTo("1.0");
        assertThat(policySet.roles()).containsKeys("developer", "devops");
        assertThat(policySet.getRole("developer")).isPresent();
        assertThat(policySet.getRole("developer").get().permissions())
            .containsExactlyInAnyOrder("git.read", "git.write", "database.query");

        assertThat(policySet.rules()).hasSize(2);
        assertThat(policySet.rules().get(0).id()).isEqualTo("deny-dev-prod-db");
        assertThat(policySet.rules().get(1).id()).isEqualTo("prod-deploy-approval");
    }

    @Test
    @DisplayName("Should seamlessly evaluate requests in DefaultPolicyEngine using loaded YAML")
    void shouldIntegrateWithDefaultPolicyEngine() {
        PolicySet policySet = loader.load(VALID_YAML);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(policySet);

        // 1. Developer in DEV -> ALLOW
        AgentIdentity devAgent = AgentIdentity.builder()
            .agentId("dev-1")
            .role("developer")
            .build();

        AuthorizationDecision devDecision = engine.evaluate(AuthorizationRequest.of(
            devAgent,
            Action.of("database.query"),
            Resource.of("database", "cust-dev-db"),
            AuthorizationContext.of("development")
        ));
        assertThat(devDecision.decision()).isEqualTo(Decision.ALLOW);

        // 2. Developer in PROD -> DENY by rule
        AuthorizationDecision prodDecision = engine.evaluate(AuthorizationRequest.of(
            devAgent,
            Action.of("database.query"),
            Resource.of("database", "cust-prod-db"),
            AuthorizationContext.of("production")
        ));
        assertThat(prodDecision.decision()).isEqualTo(Decision.DENY);
        assertThat(prodDecision.matchedRuleId()).contains("deny-dev-prod-db");

        // 3. DevOps deploy in PROD -> APPROVAL_REQUIRED
        AgentIdentity devopsAgent = AgentIdentity.builder()
            .agentId("devops-1")
            .role("devops")
            .build();

        AuthorizationDecision deployDecision = engine.evaluate(AuthorizationRequest.of(
            devopsAgent,
            Action.of("kubernetes.deploy"),
            Resource.of("k8s_cluster", "prod-cluster"),
            AuthorizationContext.of("production")
        ));
        assertThat(deployDecision.decision()).isEqualTo(Decision.APPROVAL_REQUIRED);
        assertThat(deployDecision.matchedRuleId()).contains("prod-deploy-approval");
    }

    @Test
    @DisplayName("Should reject unsupported version and fail closed")
    void shouldRejectUnsupportedVersion() {
        String badVersionYaml = """
            version: "99.0"
            roles:
              admin:
                permissions: ["*"]
            """;

        assertThatThrownBy(() -> loader.load(badVersionYaml))
            .isInstanceOf(InvalidPolicyException.class)
            .hasMessageContaining("Unsupported policy version");
    }

    @Test
    @DisplayName("Should reject missing roles section")
    void shouldRejectMissingRoles() {
        String noRolesYaml = """
            version: "1.0"
            metadata:
              name: "broken"
            """;

        assertThatThrownBy(() -> loader.load(noRolesYaml))
            .isInstanceOf(InvalidPolicyException.class)
            .hasMessageContaining("'roles' section must not be empty");
    }

    @Test
    @DisplayName("Should reject invalid rule effect (not ALLOW, DENY, or APPROVAL_REQUIRED)")
    void shouldRejectInvalidRuleEffect() {
        String badEffectYaml = """
            version: "1.0"
            roles:
              admin:
                permissions: ["*"]
            rules:
              - id: "bad-rule"
                effect: "MAYBE_ALLOW"
                target:
                  actions: ["test.action"]
            """;

        assertThatThrownBy(() -> loader.load(badEffectYaml))
            .isInstanceOf(InvalidPolicyException.class)
            .hasMessageContaining("Invalid rule effect 'MAYBE_ALLOW'");
    }

    @Test
    @DisplayName("Should reject malformed YAML indentation/syntax")
    void shouldRejectMalformedYamlSyntax() {
        String syntaxErrorYaml = """
            version: "1.0"
            roles:
              developer:
                permissions:
                - "git.read"
               bad_indentation: true
            """;

        assertThatThrownBy(() -> loader.load(syntaxErrorYaml))
            .isInstanceOf(InvalidPolicyException.class)
            .hasMessageContaining("Failed to parse YAML policy syntax");
    }

    @Test
    @DisplayName("Should reject empty or blank content")
    void shouldRejectEmptyContent() {
        assertThatThrownBy(() -> loader.load(""))
            .isInstanceOf(InvalidPolicyException.class)
            .hasMessageContaining("content is empty or blank");
    }
}
