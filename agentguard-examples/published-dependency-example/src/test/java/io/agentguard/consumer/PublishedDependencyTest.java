package io.agentguard.consumer;

import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.core.model.Decision;
import io.agentguard.mcp.error.McpAuthorizationExceptionMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(properties = "demo.enabled=false")
@Import(PublishedDependencyTest.AuditConfiguration.class)
class PublishedDependencyTest {
    @Autowired GuardedTools tools;
    @Autowired InMemoryAuditEventPublisher audit;

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
        audit.clear();
    }

    @Test
    void allowsDevelopmentAndRedactsAuditParameters() {
        authenticate("developer");
        int before = tools.executionCount();
        assertThat(tools.query("orders", "development", "secret")).contains("Simulated query");
        assertThat(tools.executionCount()).isEqualTo(before + 1);
        assertThat(audit.getEvents()).singleElement().satisfies(event -> {
            assertThat(event.decision()).isEqualTo(Decision.ALLOW);
            assertThat(event.resourceId()).isEqualTo("orders");
            assertThat(event.parameters()).containsEntry("password", "[REDACTED]");
        });
    }

    @Test
    void explicitDenyStopsExecutionAndMapsToMcpError() {
        authenticate("developer");
        int before = tools.executionCount();
        var exception = assertThrows(AgentAccessDeniedException.class,
            () -> tools.query("orders", "production", "secret"));
        var error = McpAuthorizationExceptionMapper.toMcpError(exception);
        assertThat(error.code()).isEqualTo(-32003);
        assertThat(error.data()).containsEntry("ruleId", "deny-dev-prod-db");
        assertThat(tools.executionCount()).isEqualTo(before);
        assertThat(audit.getEvents()).singleElement()
            .satisfies(event -> assertThat(event.decision()).isEqualTo(Decision.DENY));
    }

    @Test
    void approvalStopsExecutionAndMapsToMcpError() {
        authenticate("devops");
        int before = tools.executionCount();
        var exception = assertThrows(AgentApprovalRequiredException.class,
            () -> tools.deploy("orders", "production"));
        var error = McpAuthorizationExceptionMapper.toMcpError(exception);
        assertThat(error.code()).isEqualTo(-32004);
        assertThat(error.data()).containsEntry("status", "PENDING_APPROVAL");
        assertThat(tools.executionCount()).isEqualTo(before);
        assertThat(audit.getEvents()).singleElement()
            .satisfies(event -> assertThat(event.decision()).isEqualTo(Decision.APPROVAL_REQUIRED));
    }

    @Test
    void unmatchedPermissionIsDeniedByDefault() {
        authenticate("developer");
        int before = tools.executionCount();
        assertThrows(AgentAccessDeniedException.class, () -> tools.deploy("orders", "development"));
        assertThat(tools.executionCount()).isEqualTo(before);
    }

    @Test
    void missingIdentityCannotExecuteTools() {
        SecurityContextHolder.clearContext();
        int before = tools.executionCount();
        assertThrows(AgentAccessDeniedException.class,
            () -> tools.query("orders", "development", "secret"));
        assertThat(tools.executionCount()).isEqualTo(before);
    }

    @Test
    void devopsCanDeployInDevelopment() {
        authenticate("devops");
        assertThat(tools.deploy("orders", "development")).contains("Simulated deployment");
    }

    private void authenticate(String role) {
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new UsernamePasswordAuthenticationToken(
            "test-agent", "N/A", List.of(new SimpleGrantedAuthority("ROLE_" + role))));
        SecurityContextHolder.setContext(context);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class AuditConfiguration {
        @Bean
        InMemoryAuditEventPublisher auditPublisher() {
            return new InMemoryAuditEventPublisher();
        }
    }
}
