package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;
import org.slf4j.LoggerFactory;
import java.util.Objects;

public final class ReliableAuditEventPublisher implements AuditEventPublisher {
    private final AuditEventPublisher delegate;
    private final AuditFailureMode mode;
    public ReliableAuditEventPublisher(AuditEventPublisher delegate, AuditFailureMode mode) {
        this.delegate = Objects.requireNonNull(delegate); this.mode = Objects.requireNonNull(mode);
    }
    @Override
    public void publish(AuditEvent event) {
        try { delegate.publish(event); }
        catch (RuntimeException failure) {
            if (mode == AuditFailureMode.FAIL_CLOSED) throw new IllegalStateException("Audit publication failed");
            LoggerFactory.getLogger(ReliableAuditEventPublisher.class).warn("Audit publication failed; continuing in BEST_EFFORT mode");
        }
    }
}
