package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;

/**
 * Strategy interface for publishing security audit events.
 * Implementations may dispatch to SLF4J loggers, OpenTelemetry spans, Kafka topics, SIEM, or databases.
 */
public interface AuditEventPublisher {

    /**
     * Publishes a security audit event.
     *
     * @param event the immutable audit event to record
     */
    void publish(AuditEvent event);
}
