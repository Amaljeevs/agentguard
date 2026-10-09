package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;

import java.util.List;
import java.util.Objects;

/**
 * Composite implementation of {@link AuditEventPublisher} delegating to a chain of publishers.
 */
public class CompositeAuditEventPublisher implements AuditEventPublisher {

    private final List<AuditEventPublisher> publishers;
    private final AuditFailureMode failureMode;

    public CompositeAuditEventPublisher(List<AuditEventPublisher> publishers) {
        this(publishers, AuditFailureMode.BEST_EFFORT);
    }

    public CompositeAuditEventPublisher(List<AuditEventPublisher> publishers, AuditFailureMode failureMode) {
        Objects.requireNonNull(publishers, "publishers list must not be null");
        this.publishers = List.copyOf(publishers);
        this.failureMode = Objects.requireNonNull(failureMode);
    }

    public static CompositeAuditEventPublisher of(AuditEventPublisher... publishers) {
        return new CompositeAuditEventPublisher(List.of(publishers));
    }

    @Override
    public void publish(AuditEvent event) {
        if (event == null) {
            return;
        }
        boolean failed = false;
        for (AuditEventPublisher publisher : publishers) {
            try {
                publisher.publish(event);
            } catch (Exception ignored) {
                failed = true;
            }
        }
        if (failed && failureMode == AuditFailureMode.FAIL_CLOSED) throw new IllegalStateException("One or more audit publishers failed");
        if (failed) org.slf4j.LoggerFactory.getLogger(CompositeAuditEventPublisher.class)
            .warn("One or more audit publishers failed; remaining publishers were attempted");
    }

    public List<AuditEventPublisher> getPublishers() {
        return publishers;
    }
}
