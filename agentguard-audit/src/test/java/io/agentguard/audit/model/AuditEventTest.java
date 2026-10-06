package io.agentguard.audit.model;

import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.core.model.Action;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AgentType;
import io.agentguard.core.model.AuthorizationContext;
import io.agentguard.core.model.AuthorizationDecision;
import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.core.model.Decision;
import io.agentguard.core.model.Resource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AuditEvent Construction & Sanitization Tests")
class AuditEventTest {

    @Test
    @DisplayName("Should create AuditEvent from request and decision with sanitized parameters")
    void shouldCreateAuditEventWithSanitization() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("devops-01")
            .agentType(AgentType.AUTONOMOUS)
            .role("devops")
            .delegatedBy("lead-eng")
            .sessionId("sess-123")
            .build();

        Action action = Action.of("database.query", Map.of(
            "sql", "SELECT * FROM orders;",
            "db_password", "super-secret"
        ));

        Resource resource = Resource.of("database", "prod-orders");
        AuthorizationContext context = AuthorizationContext.of("production");

        AuthorizationRequest request = AuthorizationRequest.of(identity, action, resource, context);
        AuthorizationDecision decision = AuthorizationDecision.allow("Permitted by role", "enterprise-policy", "rule-01");

        AuditEvent event = AuditEvent.from(request, decision, new DefaultParameterSanitizer());

        assertThat(event.eventId()).isNotBlank();
        assertThat(event.agentId()).isEqualTo("devops-01");
        assertThat(event.agentType()).isEqualTo(AgentType.AUTONOMOUS);
        assertThat(event.roles()).containsExactly("devops");
        assertThat(event.action()).isEqualTo("database.query");
        assertThat(event.resourceType()).isEqualTo("database");
        assertThat(event.resourceId()).isEqualTo("prod-orders");
        assertThat(event.environment()).isEqualTo("production");
        assertThat(event.decision()).isEqualTo(Decision.ALLOW);
        assertThat(event.reason()).isEqualTo("Permitted by role");
        assertThat(event.matchedPolicyName()).contains("enterprise-policy");
        assertThat(event.matchedRuleId()).contains("rule-01");
        assertThat(event.delegatedBy()).contains("lead-eng");
        assertThat(event.sessionId()).contains("sess-123");

        // Verify parameters were sanitized:
        assertThat(event.parameters()).containsEntry("sql", "SELECT * FROM orders;");
        assertThat(event.parameters()).containsEntry("db_password", "[REDACTED]");
    }
}
