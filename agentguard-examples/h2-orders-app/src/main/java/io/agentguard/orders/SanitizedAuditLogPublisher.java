package io.agentguard.orders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.model.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/** Logs structured audit parameters through AgentGuard's configured sanitizer. */
public final class SanitizedAuditLogPublisher implements AuditEventPublisher {
    private static final Logger LOG = LoggerFactory.getLogger("io.agentguard.orders.audit.json");
    private final ObjectWriter writer;
    private final ParameterSanitizer sanitizer;

    public SanitizedAuditLogPublisher(ObjectMapper mapper, ParameterSanitizer sanitizer) {
        // One JSON record per line, even though API responses are pretty-printed.
        this.writer = mapper.writer().without(SerializationFeature.INDENT_OUTPUT);
        this.sanitizer = sanitizer;
    }

    @Override
    public void publish(AuditEvent event) {
        if (event == null) return;
        try {
            // AOP already sanitizes these parameters. Apply the same library sanitizer
            // at this log boundary too, so manually published events are protected.
            String json = writer.writeValueAsString(Map.of(
                "eventId", event.eventId(),
                "agentId", event.agentId(),
                "action", event.action(),
                "resourceType", event.resourceType(),
                "resourceId", event.resourceId(),
                "environment", event.environment(),
                "decision", event.decision(),
                "ruleId", event.matchedRuleId().orElse("none"),
                "parameters", sanitizer.sanitize(event.parameters())
            ));
            if (event.decision() == Decision.ALLOW) {
                LOG.info("{}", json);
            } else {
                LOG.warn("{}", json);
            }
        } catch (Exception exception) {
            // Never fall back to raw parameters or exception text, which may contain input.
            LOG.error("Could not serialize sanitized audit event");
        }
    }
}
