package io.agentguard.core.engine;

import io.agentguard.core.model.Action;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AgentType;
import io.agentguard.core.model.AuthorizationContext;
import io.agentguard.core.model.AuthorizationDecision;
import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.core.model.Decision;
import io.agentguard.core.model.PolicyRule;
import io.agentguard.core.model.PolicySet;
import io.agentguard.core.model.Resource;
import io.agentguard.core.model.RoleDefinition;
import io.agentguard.core.model.RuleEffect;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("DefaultPolicyEngine Security Matrix Tests")
class DefaultPolicyEngineTest {

    private DefaultPolicyEngine policyEngine;

    @BeforeEach
    void setUp() {
        // Build reference enterprise policy set
        RoleDefinition developerRole = RoleDefinition.of("developer", Set.of(
            "git.read",
            "git.write",
            "logs.read",
            "database.query"
        ));

        RoleDefinition devopsRole = RoleDefinition.of("devops", Set.of(
            "logs.read",
            "kubernetes.*",
            "database.*"
        ));

        RoleDefinition adminRole = RoleDefinition.of("admin", Set.of("*"));

        // Contextual rules:
        // Rule 1: Developer cannot access database in production (DENY)
        PolicyRule devProdDbDenyRule = PolicyRule.builder("deny-dev-prod-db", RuleEffect.DENY)
            .description("Developers cannot query databases in production")
            .targetRoles(Set.of("developer"))
            .targetActions(Set.of("database.query", "database.write"))
            .resourceType("database")
            .environments(Set.of("production"))
            .build();

        // Rule 2: Kubernetes deploy to production requires human approval (APPROVAL_REQUIRED)
        PolicyRule prodDeployApprovalRule = PolicyRule.builder("prod-deploy-approval", RuleEffect.APPROVAL_REQUIRED)
            .description("Deploying to production requires human approval")
            .targetActions(Set.of("kubernetes.deploy"))
            .environments(Set.of("production"))
            .build();

        PolicySet policySet = PolicySet.builder("enterprise-governance", "1.0")
            .roles(Map.of(
                "developer", developerRole,
                "devops", devopsRole,
                "admin", adminRole
            ))
            .rules(List.of(devProdDbDenyRule, prodDeployApprovalRule))
            .build();

        policyEngine = new DefaultPolicyEngine(policySet);
    }

    @Test
    @DisplayName("ALLOW: Developer agent querying database in development")
    void developerAccessInDev_shouldBeAllowed() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("dev-agent-1")
            .role("developer")
            .build();

        AuthorizationRequest request = AuthorizationRequest.of(
            identity,
            Action.of("database.query"),
            Resource.of("database", "customer-db"),
            AuthorizationContext.of("development")
        );

        AuthorizationDecision decision = policyEngine.evaluate(request);

        assertThat(decision.decision()).isEqualTo(Decision.ALLOW);
        assertThat(decision.isAllowed()).isTrue();
    }

    @Test
    @DisplayName("DENY: Developer agent querying database in production (Explicit DENY rule overrides role allow)")
    void developerAccessInProd_shouldBeDeniedByRule() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("dev-agent-1")
            .role("developer")
            .build();

        AuthorizationRequest request = AuthorizationRequest.of(
            identity,
            Action.of("database.query"),
            Resource.of("database", "customer-db"),
            AuthorizationContext.of("production")
        );

        AuthorizationDecision decision = policyEngine.evaluate(request);

        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.matchedRuleId()).contains("deny-dev-prod-db");
    }

    @Test
    @DisplayName("DENY: Missing permission for requested action")
    void missingPermission_shouldDenyByDefault() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("dev-agent-1")
            .role("developer")
            .build();

        AuthorizationRequest request = AuthorizationRequest.of(
            identity,
            Action.of("cloud.provision_bucket"),
            Resource.of("cloud_storage", "bucket-1"),
            AuthorizationContext.of("development")
        );

        AuthorizationDecision decision = policyEngine.evaluate(request);

        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reason()).contains("No matching permission or policy rule permits action");
    }

    @Test
    @DisplayName("DENY: Unknown role with no granted permissions")
    void unknownRole_shouldDenyByDefault() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("rogue-agent-99")
            .role("unknown-role")
            .build();

        AuthorizationRequest request = AuthorizationRequest.of(
            identity,
            Action.of("database.query"),
            Resource.of("database", "customer-db"),
            AuthorizationContext.of("development")
        );

        AuthorizationDecision decision = policyEngine.evaluate(request);

        assertThat(decision.decision()).isEqualTo(Decision.DENY);
    }

    @Test
    @DisplayName("DENY: Expired agent identity must fail closed")
    void expiredIdentity_shouldFailClosed() {
        Instant past = Instant.now().minus(2, ChronoUnit.HOURS);
        AgentIdentity expiredIdentity = AgentIdentity.builder()
            .agentId("expired-agent")
            .role("admin")
            .issuedAt(past.minus(1, ChronoUnit.HOURS))
            .expiresAt(past)
            .build();

        AuthorizationRequest request = AuthorizationRequest.of(
            expiredIdentity,
            Action.of("logs.read"),
            Resource.of("logs", "syslog"),
            AuthorizationContext.of("production")
        );

        AuthorizationDecision decision = policyEngine.evaluate(request);

        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reason()).contains("expired");
    }

    @Test
    @DisplayName("APPROVAL_REQUIRED: DevOps deploying to production triggers human approval")
    void prodDeploy_shouldRequireApproval() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("devops-agent-1")
            .role("devops")
            .build();

        AuthorizationRequest request = AuthorizationRequest.of(
            identity,
            Action.of("kubernetes.deploy"),
            Resource.of("k8s_cluster", "prod-cluster"),
            AuthorizationContext.of("production")
        );

        AuthorizationDecision decision = policyEngine.evaluate(request);

        assertThat(decision.decision()).isEqualTo(Decision.APPROVAL_REQUIRED);
        assertThat(decision.isApprovalRequired()).isTrue();
        assertThat(decision.matchedRuleId()).contains("prod-deploy-approval");
    }

    @Test
    @DisplayName("ALLOW: DevOps deploying to development is allowed without approval")
    void devDeploy_shouldBeAllowedDirectly() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("devops-agent-1")
            .role("devops")
            .build();

        AuthorizationRequest request = AuthorizationRequest.of(
            identity,
            Action.of("kubernetes.deploy"),
            Resource.of("k8s_cluster", "dev-cluster"),
            AuthorizationContext.of("development")
        );

        AuthorizationDecision decision = policyEngine.evaluate(request);

        assertThat(decision.decision()).isEqualTo(Decision.ALLOW);
    }

    @Test
    @DisplayName("ALLOW: Universal wildcard (*) permits all actions")
    void adminUniversalWildcard_shouldAllow() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("admin-agent")
            .role("admin")
            .build();

        AuthorizationRequest request = AuthorizationRequest.of(
            identity,
            Action.of("infra.destroy"),
            Resource.of("server", "srv-01"),
            AuthorizationContext.of("staging")
        );

        AuthorizationDecision decision = policyEngine.evaluate(request);

        assertThat(decision.decision()).isEqualTo(Decision.ALLOW);
    }
}
