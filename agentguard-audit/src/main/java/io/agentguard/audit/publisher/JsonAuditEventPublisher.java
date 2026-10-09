package io.agentguard.audit.publisher;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.model.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.LinkedHashMap;
import java.util.Objects;

/** Single-line structured audit logging; only sanitized structured data reaches the logger. */
public final class JsonAuditEventPublisher implements AuditEventPublisher {
    private final ParameterSanitizer sanitizer;
    private final Logger logger;
    private final ObjectMapper mapper = new ObjectMapper();

    public JsonAuditEventPublisher(ParameterSanitizer sanitizer) {
        this(sanitizer, LoggerFactory.getLogger("io.agentguard.audit.json"));
    }

    public JsonAuditEventPublisher(ParameterSanitizer sanitizer, Logger logger) {
        this.sanitizer = Objects.requireNonNull(sanitizer);
        this.logger = Objects.requireNonNull(logger);
    }

    @Override
    public void publish(AuditEvent event) {
        if (event == null) return;
        try {
            var data = new LinkedHashMap<String, Object>();
            data.put("eventId", event.eventId()); data.put("timestamp", event.timestamp().toString());
            data.put("agentId", event.agentId()); data.put("action", event.action());
            data.put("resourceType", event.resourceType()); data.put("resourceId", event.resourceId());
            data.put("environment", event.environment()); data.put("decision", event.decision().name());
            data.put("ruleId", event.matchedRuleId().orElse(null));
            data.put("delegatedBy", event.delegatedBy().orElse(null));
            data.put("parameters", sanitizer.sanitize(event.parameters()));
            data.put("metadata", sanitizer.sanitize(event.metadata()));
            String json = mapper.writeValueAsString(data);
            if (event.decision() == Decision.ALLOW && !"EXECUTION_FAILED".equals(event.metadata().get("phase"))) logger.info("{}", json);
            else logger.warn("{}", json);
        } catch (Exception failure) {
            // No throwable, request contents or serialization message is logged.
            throw new IllegalStateException("Could not publish sanitized JSON audit event");
        }
    }
}
