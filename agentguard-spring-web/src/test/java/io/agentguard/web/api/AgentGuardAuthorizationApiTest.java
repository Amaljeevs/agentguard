package io.agentguard.web.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.approval.*;
import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.core.engine.*;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

class AgentGuardAuthorizationApiTest {
    private final AgentIdentity trusted = AgentIdentity.builder().agentId("verified-agent")
        .permission("kubernetes.deploy").issuedAt(Instant.now().minusSeconds(60))
        .expiresAt(Instant.now().plusSeconds(3600)).build();
    private final PolicySet policy = PolicySet.builder("deploy-policy", "2026-10")
        .rules(List.of(PolicyRule.builder("human-review", RuleEffect.APPROVAL_REQUIRED)
            .targetActions(Set.of("kubernetes.deploy")).risk(RiskLevel.CRITICAL).build())).build();
    private final PolicyEngine engine = new DefaultPolicyEngine(policy);
    private final InMemoryAuditEventPublisher audit = new InMemoryAuditEventPublisher();
    private final DefaultParameterSanitizer sanitizer = new DefaultParameterSanitizer();

    @Test void returnsLanguageNeutralMetadataAndCreatesBoundApproval() {
        var approval = new ApprovalService(engine, new InMemoryApprovalStore(), Clock.systemUTC(), audit, sanitizer);
        var api = new AgentGuardAuthorizationApi(engine, () -> Optional.of(trusted), audit, sanitizer,
            Optional.of(approval), Duration.ofMinutes(5));
        var input = new AuthorizationApiRequest("verified-agent", "kubernetes.deploy",
            new AuthorizationApiRequest.ApiResource("cluster", "prod-a", Map.of()),
            Map.of("image", "v2", "token", "secret"), Map.of("environment", "production", "traceId", "trace-api"));

        var response = api.authorize(input);
        assertThat(response.decision()).isEqualTo(Decision.APPROVAL_REQUIRED);
        assertThat(response.matchedPolicy()).isEqualTo("deploy-policy");
        assertThat(response.policyVersion()).isEqualTo("2026-10");
        assertThat(response.policyHash()).hasSize(64);
        assertThat(response.risk()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(response.approvalRequestId()).isNotBlank();
        assertThat(response.traceId()).isEqualTo("trace-api");
        assertThat(audit.getEvents()).allMatch(event -> !event.toString().contains("secret"));
    }

    @Test void payloadPrincipalCannotForgeTheAuthenticatedIdentity() {
        var api = new AgentGuardAuthorizationApi(engine, () -> Optional.of(trusted), audit, sanitizer);
        var forged = new AuthorizationApiRequest("admin", "kubernetes.deploy",
            new AuthorizationApiRequest.ApiResource("cluster", "prod", Map.of()), Map.of(),
            Map.of("environment", "production"));
        assertThatThrownBy(() -> api.authorize(forged)).isInstanceOf(AgentAccessDeniedException.class);
    }

    @Test void principalObjectsWithInjectedRolesAreRejectedByTheJsonContract() {
        String forged = """
            {"principal":{"id":"verified-agent","roles":["admin"]},"action":"kubernetes.deploy",
             "resource":{"type":"cluster","id":"prod"},"arguments":{},"context":{"environment":"production"}}
            """;
        assertThatThrownBy(() -> new ObjectMapper().readValue(forged, AuthorizationApiRequest.class))
            .isInstanceOf(Exception.class);

        String topLevelRoles = """
            {"principal":"verified-agent","roles":["admin"],"action":"kubernetes.deploy",
             "resource":{"type":"cluster","id":"prod"},"arguments":{},"context":{"environment":"production"}}
            """;
        assertThatThrownBy(() -> new ObjectMapper().readValue(topLevelRoles, AuthorizationApiRequest.class))
            .isInstanceOf(Exception.class);
    }

    @Test void postAuthorizeExposesTheLanguageNeutralJsonContract() throws Exception {
        var api = new AgentGuardAuthorizationApi(engine, () -> Optional.of(trusted), audit, sanitizer);
        MockMvc mvc = standaloneSetup(new AuthorizationController(api))
            .setControllerAdvice(new AuthorizationApiExceptionHandler()).build();
        var result = mvc.perform(post("/v1/authorize").contentType("application/json").content("""
            {"principal":"verified-agent","action":"kubernetes.deploy",
             "resource":{"type":"cluster","id":"prod-a"},"arguments":{"image":"v2"},
             "context":{"environment":"production","traceId":"trace-http"}}
            """)).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        var json = new ObjectMapper().readTree(result.getResponse().getContentAsString());
        assertThat(json.get("decision").asText()).isEqualTo("APPROVAL_REQUIRED");
        assertThat(json.get("matchedPolicy").asText()).isEqualTo("deploy-policy");
        assertThat(json.get("policyVersion").asText()).isEqualTo("2026-10");
        assertThat(json.get("risk").asText()).isEqualTo("CRITICAL");
        assertThat(json.get("traceId").asText()).isEqualTo("trace-http");
    }
}
