package io.agentguard.core.model.condition;

import io.agentguard.core.model.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RuleConditions Scope and Matching Tests")
class RuleConditionsTest {

    @Test
    void testArgumentConditionsMatching() {
        RuleConditions conditions = RuleConditions.builder()
            .argument("amount", ConditionOperator.GREATER_THAN, 50000)
            .argument("currency", ConditionOperator.IN, List.of("USD", "SAR", "EUR"))
            .build();

        // Matching request
        AuthorizationRequest reqPass = createRequest(
            Map.of("amount", 75000, "currency", "USD"),
            Map.of(),
            Map.of(),
            "production"
        );
        assertThat(conditions.matches(reqPass)).isTrue();

        // Amount below threshold -> false
        AuthorizationRequest reqBelow = createRequest(
            Map.of("amount", 25000, "currency", "USD"),
            Map.of(),
            Map.of(),
            "production"
        );
        assertThat(conditions.matches(reqBelow)).isFalse();

        // Currency not in list -> false
        AuthorizationRequest reqCurrencyFail = createRequest(
            Map.of("amount", 75000, "currency", "JPY"),
            Map.of(),
            Map.of(),
            "production"
        );
        assertThat(conditions.matches(reqCurrencyFail)).isFalse();

        // Missing argument -> false
        AuthorizationRequest reqMissing = createRequest(
            Map.of("amount", 75000),
            Map.of(),
            Map.of(),
            "production"
        );
        assertThat(conditions.matches(reqMissing)).isFalse();
    }

    @Test
    void testSubjectAttributesAndTenantMatching() {
        RuleConditions conditions = RuleConditions.builder()
            .subjectAttribute("department", ConditionOperator.EQUALS, "treasury")
            .tenant(ConditionOperator.EQUALS, "tenant-banking-corp")
            .build();

        AuthorizationRequest match = createRequest(
            Map.of(),
            Map.of("department", "treasury", "tenant", "tenant-banking-corp"),
            Map.of(),
            "production"
        );
        assertThat(conditions.matches(match)).isTrue();

        AuthorizationRequest wrongDept = createRequest(
            Map.of(),
            Map.of("department", "marketing", "tenant", "tenant-banking-corp"),
            Map.of(),
            "production"
        );
        assertThat(conditions.matches(wrongDept)).isFalse();

        AuthorizationRequest wrongTenant = createRequest(
            Map.of(),
            Map.of("department", "treasury", "tenant", "tenant-other"),
            Map.of(),
            "production"
        );
        assertThat(conditions.matches(wrongTenant)).isFalse();
    }

    @Test
    void testResourceTagsAndEnvironmentMatching() {
        RuleConditions conditions = RuleConditions.builder()
            .resourceTag("confidentiality", ConditionOperator.EQUALS, "strict")
            .environment(ConditionOperator.IN, List.of("staging", "production"))
            .build();

        AuthorizationRequest match = createRequest(
            Map.of(),
            Map.of(),
            Map.of("confidentiality", "strict"),
            "production"
        );
        assertThat(conditions.matches(match)).isTrue();

        AuthorizationRequest devEnv = createRequest(
            Map.of(),
            Map.of(),
            Map.of("confidentiality", "strict"),
            "development"
        );
        assertThat(conditions.matches(devEnv)).isFalse();

        AuthorizationRequest missingTag = createRequest(
            Map.of(),
            Map.of(),
            Map.of(),
            "production"
        );
        assertThat(conditions.matches(missingTag)).isFalse();
    }

    private AuthorizationRequest createRequest(
        Map<String, Object> parameters,
        Map<String, Object> subjectAttrs,
        Map<String, String> resourceTags,
        String environment
    ) {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("agent-test")
            .agentType(AgentType.AUTONOMOUS)
            .roles(Set.of("payment-agent"))
            .permissions(Set.of("payments.*"))
            .issuedAt(Instant.now().minusSeconds(60))
            .expiresAt(Instant.now().plusSeconds(3600))
            .attributes(subjectAttrs)
            .build();

        Action action = Action.of("payments.transfer", parameters);
        Resource resource = Resource.of("account", "ACC-001", resourceTags);
        AuthorizationContext context = AuthorizationContext.of(environment);

        return AuthorizationRequest.of(identity, action, resource, context);
    }
}

