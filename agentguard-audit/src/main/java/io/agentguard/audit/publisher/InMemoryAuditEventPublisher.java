package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe in-memory implementation of {@link AuditEventPublisher} capturing events for testing and inspection.
 */
public class InMemoryAuditEventPublisher implements AuditEventPublisher {

    private final List<AuditEvent> events = new CopyOnWriteArrayList<>();

    @Override
    public void publish(AuditEvent event) {
        if (event != null) {
            events.add(event);
        }
    }

    public List<AuditEvent> getEvents() {
        return Collections.unmodifiableList(new ArrayList<>(events));
    }

    public void clear() {
        events.clear();
    }

    public int size() {
        return events.size();
    }
}
