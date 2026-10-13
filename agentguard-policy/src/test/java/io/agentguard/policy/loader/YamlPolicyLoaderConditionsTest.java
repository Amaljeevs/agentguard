package io.agentguard.policy.loader;

import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.exception.InvalidPolicyException;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("YamlPolicyLoader Conditions & Policy Engine Integration Tests")
class YamlPolicyLoaderConditionsTest {

    private final YamlPolicyLoader loader = new YamlPolicyLoader();

    @Test
    void testLoadsAndEnforcesDeclarativeConditions() {
        String yaml = """
            version: "1.0"
            metadata:
              name: "fintech-transfers"
              version: "2026-10"
            roles:
              treasury-operator:
                description: "Treasury operator"
                permissions:
                  - payments.*
            rules:
              - id: high-value-transfer
                effect: APPROVAL_REQUIRED
                risk: HIGH
                target:
                  actions:
                    - payments.transfer
                conditions:
                  arguments:
                    amount:
                      greaterThan: 50000
                  environment:
                    equals: production
                  subject:
                    attributes:
                      department:
                        equals: treasury
            """;

        PolicySet policySet = loader.load(yaml);
        assertThat(policySet.rules()).hasSize(1);
        PolicyRule rule = policySet.rules().get(0);
        assertThat(rule.conditions()).isPresent();

        DefaultPolicyEngine engine = new DefaultPolicyEngine(policySet);

        AgentIdentity subjectTreasury = AgentIdentity.builder()
            .agentId("agent-1")
            .agentType(AgentType.AUTONOMOUS)
            .roles(Set.of("treasury-operator"))
            .issuedAt(Instant.now().minusSeconds(60))
            .expiresAt(Instant.now().plusSeconds(3600))
            .attributes(Map.of("department", "treasury"))
            .build();

        // 1. Production transfer with amount 75000 -> APPROVAL_REQUIRED
        AuthorizationRequest reqHigh = AuthorizationRequest.of(
            subjectTreasury,
            Action.of("payments.transfer", Map.of("amount", 75000)),
            Resource.of("account", "ACC-100"),
            AuthorizationContext.of("production")
        );
        AuthorizationDecision decisionHigh = engine.evaluate(reqHigh);
        assertThat(decisionHigh.isApprovalRequired()).isTrue();
        assertThat(decisionHigh.matchedRuleId()).hasValue("high-value-transfer");

        // 2. Production transfer with amount 25000 -> ALLOW (condition not met, role grant applies)
        AuthorizationRequest reqLow = AuthorizationRequest.of(
            subjectTreasury,
            Action.of("payments.transfer", Map.of("amount", 25000)),
            Resource.of("account", "ACC-100"),
            AuthorizationContext.of("production")
        );
        AuthorizationDecision decisionLow = engine.evaluate(reqLow);
        assertThat(decisionLow.isAllowed()).isTrue();

        // 3. Staging transfer with amount 75000 -> ALLOW (environment condition not met)
        AuthorizationRequest reqStaging = AuthorizationRequest.of(
            subjectTreasury,
            Action.of("payments.transfer", Map.of("amount", 75000)),
            Resource.of("account", "ACC-100"),
            AuthorizationContext.of("staging")
        );
        assertThat(engine.evaluate(reqStaging).isAllowed()).isTrue();

        // 4. Marketing department agent with amount 75000 -> ALLOW via role grant
        AgentIdentity subjectMarketing = AgentIdentity.builder()
            .agentId("agent-2")
            .agentType(AgentType.AUTONOMOUS)
            .roles(Set.of("treasury-operator"))
            .issuedAt(Instant.now().minusSeconds(60))
            .expiresAt(Instant.now().plusSeconds(3600))
            .attributes(Map.of("department", "marketing"))
            .build();
        AuthorizationRequest reqMarketing = AuthorizationRequest.of(
            subjectMarketing,
            Action.of("payments.transfer", Map.of("amount", 75000)),
            Resource.of("account", "ACC-100"),
            AuthorizationContext.of("production")
        );
        assertThat(engine.evaluate(reqMarketing).isAllowed()).isTrue();
    }

    @Test
    void testDenyPrecedenceWithConditions() {
        String yaml = """
            version: "1.0"
            roles:
              treasury-operator:
                permissions:
                  - payments.*
            rules:
              - id: deny-sanctioned-destination
                effect: DENY
                risk: CRITICAL
                target:
                  actions:
                    - payments.transfer
                conditions:
                  arguments:
                    destinationCountry:
                      in:
                        - SANCTIONED_X
                        - SANCTIONED_Y
              - id: high-value-transfer
                effect: APPROVAL_REQUIRED
                target:
                  actions:
                    - payments.transfer
                conditions:
                  arguments:
                    amount:
                      greaterThan: 50000
            """;

        PolicySet policySet = loader.load(yaml);
        DefaultPolicyEngine engine = new DefaultPolicyEngine(policySet);

        AgentIdentity subject = AgentIdentity.builder()
            .agentId("agent-1")
            .roles(Set.of("treasury-operator"))
            .issuedAt(Instant.now().minusSeconds(60))
            .expiresAt(Instant.now().plusSeconds(3600))
            .build();

        // Both conditions match: amount > 50000 AND destinationCountry = SANCTIONED_X
        // DENY must strictly take precedence over APPROVAL_REQUIRED!
        AuthorizationRequest reqSanctioned = AuthorizationRequest.of(
            subject,
            Action.of("payments.transfer", Map.of("amount", 100000, "destinationCountry", "SANCTIONED_X")),
            Resource.of("account", "ACC-100"),
            AuthorizationContext.of("production")
        );
        AuthorizationDecision decision = engine.evaluate(reqSanctioned);
        assertThat(decision.isDenied()).isTrue();
        assertThat(decision.matchedRuleId()).hasValue("deny-sanctioned-destination");
    }

    @Test
    void testUnknownConditionOperatorFailsClosedAtLoadTime() {
        String yamlWithInvalidOperator = """
            version: "1.0"
            roles:
              dev:
                permissions:
                  - "*"
            rules:
              - id: unsafe-rule
                effect: DENY
                conditions:
                  arguments:
                    payload:
                      evalJs: "return true;"
            """;

        assertThatThrownBy(() -> loader.load(yamlWithInvalidOperator))
            .isInstanceOf(InvalidPolicyException.class)
            .hasMessageContaining("Unsupported condition operator: 'evalJs'");
    }
}

