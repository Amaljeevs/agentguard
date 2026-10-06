package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;

import java.util.List;
import java.util.Objects;

/**
 * Composite implementation of {@link AuditEventPublisher} delegating to a chain of publishers.
 */
public class CompositeAuditEventPublisher implements AuditEventPublisher {

    private final List<AuditEventPublisher> publishers;

    public CompositeAuditEventPublisher(List<AuditEventPublisher> publishers) {
        Objects.requireNonNull(publishers, "publishers list must not be null");
        this.publishers = List.copyOf(publishers);
    }

    public static CompositeAuditEventPublisher of(AuditEventPublisher... publishers) {
        return new CompositeAuditEventPublisher(List.of(publishers));
    }

    @Override
    public void publish(AuditEvent event) {
        if (event == null) {
            return;
        }
        for (AuditEventPublisher publisher : publishers) {
            try {
                publisher.publish(event);
            } catch (Exception ignored) {
                // Individual publisher failures must not prevent remaining publishers from receiving audit events
            }
        }
    }

    public List<AuditEventPublisher> getPublishers() {
        return publishers;
    }
}
