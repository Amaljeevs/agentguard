package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;
import io.agentguard.core.model.Decision;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Standard implementation of {@link AuditEventPublisher} writing structured audit records to SLF4J.
 * Denials and approval requests are logged at WARN level; allowed evaluations are logged at INFO level.
 */
public class Slf4jAuditEventPublisher implements AuditEventPublisher {

    private static final Logger AUDIT_LOG = LoggerFactory.getLogger("io.agentguard.audit");

    private final Logger logger;

    public Slf4jAuditEventPublisher() {
        this(AUDIT_LOG);
    }

    public Slf4jAuditEventPublisher(Logger logger) {
        this.logger = Objects.requireNonNull(logger, "logger must not be null");
    }

    @Override
    public void publish(AuditEvent event) {
        if (event == null) {
            return;
        }

        String logMessage = String.format(
            "[AgentGuard-Audit] id=%s decision=%s agentId=%s action=%s resource=%s:%s env=%s reason=\"%s\" delegatedBy=%s rule=%s",
            event.eventId(),
            event.decision(),
            event.agentId(),
            event.action(),
            event.resourceType(),
            event.resourceId(),
            event.environment(),
            event.reason(),
            event.delegatedBy().orElse("none"),
            event.matchedRuleId().orElse("none")
        );

        if (event.decision() == Decision.DENY || event.decision() == Decision.APPROVAL_REQUIRED) {
            logger.warn(logMessage);
        } else {
            logger.info(logMessage);
        }
    }
}
