package io.agentguard.example;

import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.example.tools.DatabaseTools;
import io.agentguard.example.tools.KubernetesTools;
import io.agentguard.example.tools.LogTools;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@DisplayName("SpringMcpExampleApplication End-to-End Governance Tests")
class SpringMcpExampleApplicationTest {

    @Autowired
    private DatabaseTools databaseTools;

    @Autowired
    private KubernetesTools kubernetesTools;

    @Autowired
    private LogTools logTools;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private void authenticateAs(String agentId, String... roles) {
        List<SimpleGrantedAuthority> authorities = java.util.Arrays.stream(roles)
            .map(r -> new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()))
            .toList();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
            agentId,
            "N/A",
            authorities
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Test
    @DisplayName("ALLOW: Developer agent queries database in development")
    void developerInDev_shouldBeAllowed() {
        authenticateAs("coding-agent-17", "DEVELOPER");

        List<Map<String, Object>> result = databaseTools.queryDatabase("cust-dev-db", "SELECT * FROM dev_data;", "development");

        assertThat(result).isNotEmpty();
        assertThat(result.get(0)).containsEntry("db", "cust-dev-db");
    }

    @Test
    @DisplayName("DENY: Developer agent querying database in production is blocked by rule 'deny-dev-prod-db'")
    void developerInProd_shouldBeDenied() {
        authenticateAs("coding-agent-17", "DEVELOPER");

        assertThatThrownBy(() ->
            databaseTools.queryDatabase("cust-prod-db", "SELECT * FROM prod_data;", "production")
        ).isInstanceOf(AgentAccessDeniedException.class)
         .hasMessageContaining("deny-dev-prod-db");
    }

    @Test
    @DisplayName("APPROVAL_REQUIRED: DevOps deploying to production triggers approval workflow")
    void devopsDeployProd_shouldRequireApproval() {
        authenticateAs("devops-agent-01", "DEVOPS");

        assertThatThrownBy(() ->
            kubernetesTools.deployService("prod-cluster-01", "payment-service", "v2.0", "production")
        ).isInstanceOf(AgentApprovalRequiredException.class)
         .hasMessageContaining("prod-deploy-approval");
    }

    @Test
    @DisplayName("ALLOW: DevOps deploying to development is permitted directly")
    void devopsDeployDev_shouldBeAllowed() {
        authenticateAs("devops-agent-01", "DEVOPS");

        Map<String, Object> result = kubernetesTools.deployService("dev-cluster-01", "payment-service", "v2.0", "development");

        assertThat(result).containsEntry("status", "DEPLOYED");
        assertThat(result).containsEntry("cluster", "dev-cluster-01");
    }

    @Test
    @DisplayName("ALLOW: Developer agent reading logs is permitted")
    void developerReadingLogs_shouldBeAllowed() {
        authenticateAs("coding-agent-17", "DEVELOPER");

        List<String> logs = logTools.fetchRecentLogs("order-service", 50);

        assertThat(logs).isNotEmpty();
    }

    @Test
    @DisplayName("DENY: Unauthenticated caller is denied by default")
    void unauthenticatedCaller_shouldBeDenied() {
        SecurityContextHolder.clearContext();

        assertThatThrownBy(() ->
            logTools.fetchRecentLogs("order-service", 10)
        ).isInstanceOf(AgentAccessDeniedException.class)
         .hasMessageContaining("No authenticated agent identity found");
    }
}
