package io.agentguard.orders;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.model.*;
import io.agentguard.spring.annotation.AgentAuthorize;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class InspectionService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final InMemoryAuditEventPublisher recent;
    private final AuditEventPublisher publisher;
    private final PolicyEngine engine;
    private final ParameterSanitizer sanitizer;

    public InspectionService(JdbcTemplate jdbc, ObjectMapper mapper, InMemoryAuditEventPublisher recent,
                             AuditEventPublisher publisher, PolicyEngine engine, ParameterSanitizer sanitizer) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.recent = recent;
        this.publisher = publisher;
        this.engine = engine;
        this.sanitizer = sanitizer;
    }

    @AgentAuthorize("audit.read")
    public Map<String, Object> audits() {
        List<JsonNode> events = jdbc.query("SELECT event_json FROM audit_event ORDER BY sequence_id DESC LIMIT 100",
            (rs, row) -> {
                try { return mapper.readTree(rs.getString(1)); }
                catch (Exception exception) { throw new IllegalStateException("Invalid stored audit JSON", exception); }
            });
        return Map.of("events", events, "inMemoryCount", recent.size(),
            "sqlCount", jdbc.queryForObject("SELECT COUNT(*) FROM audit_event", Long.class));
    }

    @AgentAuthorize("policy.preview")
    public Map<String, AuthorizationDecision> previews() {
        Instant now = Instant.now();
        var result = new LinkedHashMap<String, AuthorizationDecision>();
        evaluate(result, "expired-identity", AgentIdentity.builder().agentId("expired-demo")
            .role("operator").issuedAt(now.minusSeconds(120)).expiresAt(now.minusSeconds(60)).build(), "orders.read");
        evaluate(result, "direct-permission", AgentIdentity.builder().agentId("direct-demo")
            .permission("orders.read").build(), "orders.read");
        evaluate(result, "delegated-lineage", AgentIdentity.builder().agentId("worker-demo")
            .agentType(AgentType.WORKER).permission("orders.read").delegatedBy("supervisor-demo")
            .sessionId("demo-session").attribute("team", "support").build(), "orders.read");
        evaluate(result, "default-deny", AgentIdentity.builder().agentId("unprivileged-demo").build(), "orders.read");
        return result;
    }

    private void evaluate(Map<String, AuthorizationDecision> result, String label, AgentIdentity identity, String action) {
        var request = AuthorizationRequest.of(identity,
            Action.of(action, Map.of("token", "preview-secret")), Resource.of("database", "orders-dev"),
            AuthorizationContext.of("development", Map.of("preview", true)));
        var decision = engine.evaluate(request);
        publisher.publish(AuditEvent.from(request, decision, sanitizer));
        result.put(label, decision);
    }
}
