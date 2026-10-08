package io.agentguard.orders;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class OrdersAppTest {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired ObjectMapper mapper;
    @Autowired InMemoryAuditEventPublisher memory;

    @BeforeEach
    void resetDatabase() {
        jdbc.update("DELETE FROM refund_approval");
        jdbc.update("DELETE FROM demo_order");
        jdbc.update("DELETE FROM audit_event");
        jdbc.update("INSERT INTO demo_order (id, database_id, product, customer_email, amount) VALUES "
            + "(1, 'orders-dev', 'Dev plan', 'dev@example.test', 29), "
            + "(2, 'orders-prod', 'Prod plan', 'prod@example.test', 149)");
        jdbc.execute("ALTER TABLE demo_order ALTER COLUMN id RESTART WITH 3");
        memory.clear();
    }

    @Test
    void realCredentialsAuthenticateAndBadCredentialsFail() throws Exception {
        mvc.perform(get("/api/session").with(httpBasic("developer", "demo-pass")))
            .andExpect(status().isOk()).andExpect(jsonPath("$.username").value("developer"))
            .andExpect(jsonPath("$.csrfToken").isNotEmpty());
        mvc.perform(get("/api/session").with(httpBasic("developer", "wrong"))).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/databases/orders-dev/orders")).andExpect(status().isUnauthorized());
    }

    @Test
    void csrfIsRequiredForMutations() throws Exception {
        mvc.perform(post("/api/orders/1/refund").with(role("operator"))).andExpect(status().isForbidden());
        assertThat(orderStatus(1)).isEqualTo("PAID");
    }

    @Test
    void developerCanQueryDevelopmentButCannotQueryProduction() throws Exception {
        mvc.perform(get("/api/databases/orders-dev/orders").with(role("developer")))
            .andExpect(status().isOk()).andExpect(jsonPath("$[0].id").value(1));
        mvc.perform(get("/api/databases/orders-prod/orders").with(role("developer")))
            .andExpect(status().isForbidden()).andExpect(jsonPath("$.error.code").value(-32003))
            .andExpect(jsonPath("$.error.data.ruleId").value("developer-production-denied"));
    }

    @Test
    void parameterizedInsertPersistsDataAndRedactsNestedAuditSecrets() throws Exception {
        String payload = """
            {"product":"Robert'); DROP TABLE demo_order;--", "customerEmail":"private@example.test",
             "amount":39.50, "password":"top-secret", "internalNote":"private-note",
             "integration":{"api_key":"nested-secret","region":"local"},
             "attempts":[{"token":"list-secret","result":"ok"}]}
            """;
        mvc.perform(post("/api/databases/orders-dev/orders").with(role("developer")).with(csrf())
                .contentType("application/json").content(payload))
            .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("PAID"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM demo_order", Integer.class)).isEqualTo(3);
        assertThat(jdbc.queryForObject("SELECT product FROM demo_order WHERE id=3", String.class))
            .isEqualTo("Robert'); DROP TABLE demo_order;--");
        String auditJson = jdbc.queryForObject("SELECT event_json FROM audit_event", String.class);
        assertThat(auditJson).doesNotContain("top-secret", "private@example.test", "private-note", "nested-secret", "list-secret");
        var payloadAudit = mapper.readTree(auditJson).path("parameters").path("payload");
        assertThat(payloadAudit.path("password").asText()).isEqualTo("[HIDDEN]");
        assertThat(payloadAudit.path("customerEmail").asText()).isEqualTo("[HIDDEN]");
        assertThat(payloadAudit.path("internalNote").asText()).isEqualTo("[HIDDEN]");
        assertThat(payloadAudit.path("integration").path("api_key").asText()).isEqualTo("[HIDDEN]");
        assertThat(payloadAudit.path("integration").path("region").asText()).isEqualTo("local");
        assertThat(payloadAudit.path("attempts").get(0).path("token").asText()).isEqualTo("[HIDDEN]");
        assertThat(memory.size()).isEqualTo(1);
    }

    @Test
    void deniedInsertNeverChangesDatabase() throws Exception {
        mvc.perform(post("/api/databases/orders-prod/orders").with(role("developer")).with(csrf())
                .contentType("application/json").content("""
                    {"product":"Blocked", "customerEmail":"demo@example.test", "amount":12}
                    """))
            .andExpect(status().isForbidden());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM demo_order", Integer.class)).isEqualTo(2);
        assertThat(memory.getEvents().getFirst().decision().name()).isEqualTo("DENY");
    }

    @Test
    void productionRefundNeedsDifferentApproverAndCannotBeReplayed() throws Exception {
        String id = requestProductionRefund();
        assertThat(orderStatus(2)).isEqualTo("PAID");
        mvc.perform(post("/api/approvals/" + id + "/approve").with(role("operator")).with(csrf()))
            .andExpect(status().isForbidden());
        assertThat(orderStatus(2)).isEqualTo("PAID");
        mvc.perform(post("/api/approvals/" + id + "/approve").with(role("approver")).with(csrf()))
            .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("REFUNDED"));
        assertThat(orderStatus(2)).isEqualTo("REFUNDED");
        assertThat(jdbc.queryForObject("SELECT approved_by FROM refund_approval WHERE id=?", String.class, id))
            .isEqualTo("approver");
        mvc.perform(post("/api/approvals/" + id + "/approve").with(role("approver")).with(csrf()))
            .andExpect(status().isConflict());
    }

    @Test
    void requesterCannotSelfApproveEvenWithApproverRole() throws Exception {
        String id = requestProductionRefund();
        mvc.perform(post("/api/approvals/" + id + "/approve")
                .with(user("operator").roles("APPROVER")).with(csrf()))
            .andExpect(status().isForbidden());
        assertThat(orderStatus(2)).isEqualTo("PAID");
    }

    @Test
    void explicitDenyOverridesWildcardAndApprovalRules() throws Exception {
        mvc.perform(delete("/api/orders/2").with(role("operator")).with(csrf()))
            .andExpect(status().isForbidden()).andExpect(jsonPath("$.error.data.ruleId").value("no-production-delete"));
        mvc.perform(post("/api/orders/2/refund").with(user("combined").roles("DEVELOPER", "OPERATOR")).with(csrf()))
            .andExpect(status().isForbidden()).andExpect(jsonPath("$.error.data.ruleId").value("developer-production-denied"));
        assertThat(orderStatus(2)).isEqualTo("PAID");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM refund_approval", Integer.class)).isZero();
    }

    @Test
    void wildcardPermissionAllowsDevelopmentDeleteAndDefaultDenyBlocksDeveloper() throws Exception {
        mvc.perform(delete("/api/orders/1").with(role("developer")).with(csrf()))
            .andExpect(status().isForbidden());
        mvc.perform(delete("/api/orders/1").with(role("operator")).with(csrf()))
            .andExpect(status().isNoContent());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM demo_order WHERE id=1", Integer.class)).isZero();
    }

    @Test
    void resourceSpecificAllowIsLimitedToDevelopmentDatabase() throws Exception {
        mvc.perform(get("/api/databases/orders-dev/orders").with(role("auditor"))).andExpect(status().isOk());
        assertThat(memory.getEvents().getFirst().matchedRuleId()).contains("auditor-development-read");
        mvc.perform(get("/api/databases/orders-prod/orders").with(role("auditor"))).andExpect(status().isForbidden());
    }

    @Test
    void developmentRefundExecutesImmediately() throws Exception {
        mvc.perform(post("/api/orders/1/refund").with(role("developer")).with(csrf()))
            .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("REFUNDED"));
        assertThat(orderStatus(1)).isEqualTo("REFUNDED");
    }

    @Test
    void corePreviewsShowExpiryDirectPermissionsAndDelegationAuditMetadata() throws Exception {
        mvc.perform(post("/api/policy-preview").with(role("auditor")).with(csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$['expired-identity'].decision").value("DENY"))
            .andExpect(jsonPath("$['direct-permission'].decision").value("ALLOW"))
            .andExpect(jsonPath("$['delegated-lineage'].decision").value("ALLOW"))
            .andExpect(jsonPath("$['default-deny'].decision").value("DENY"));
        assertThat(memory.getEvents()).anySatisfy(event -> {
            assertThat(event.agentId()).isEqualTo("worker-demo");
            assertThat(event.delegatedBy()).contains("supervisor-demo");
            assertThat(event.sessionId()).contains("demo-session");
            assertThat(event.parameters()).containsEntry("token", "[HIDDEN]");
        });
        mvc.perform(get("/api/audit").with(role("auditor"))).andExpect(status().isOk())
            .andExpect(jsonPath("$.sqlCount").value(6)).andExpect(jsonPath("$.inMemoryCount").value(6));
    }

    @Test
    void rejectsNullPayloadValuesUnknownDatabasesAndInvalidAmounts() throws Exception {
        mvc.perform(post("/api/databases/orders-dev/orders").with(role("developer")).with(csrf())
                .contentType("application/json").content("{\"nested\":[null]}"))
            .andExpect(status().isBadRequest());
        mvc.perform(get("/api/databases/unknown/orders").with(role("operator"))).andExpect(status().isNotFound());
        mvc.perform(post("/api/databases/orders-dev/orders").with(role("developer")).with(csrf())
                .contentType("application/json").content("""
                    {"product":"Test","customerEmail":"demo@example.test","amount":-1}
                    """))
            .andExpect(status().isBadRequest());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM demo_order", Integer.class)).isEqualTo(2);
    }

    private String requestProductionRefund() throws Exception {
        var response = mvc.perform(post("/api/orders/2/refund?environment=development")
                .with(role("operator")).with(csrf()))
            .andExpect(status().isAccepted()).andExpect(jsonPath("$.error.code").value(-32004))
            .andReturn().getResponse().getContentAsString();
        return mapper.readTree(response).path("approvalId").asText();
    }

    private String orderStatus(long id) {
        return jdbc.queryForObject("SELECT status FROM demo_order WHERE id=?", String.class, id);
    }

    private RequestPostProcessor role(String name) { return user(name).roles(name.toUpperCase(java.util.Locale.ROOT)); }
}
