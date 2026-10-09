package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;
import java.util.*;

/** Bounded, thread-safe recent-event buffer for tests and inspection; not a durable audit store. */
public class InMemoryAuditEventPublisher implements AuditEventPublisher {
    private final Deque<AuditEvent> events = new ArrayDeque<>();
    private final int capacity;
    public InMemoryAuditEventPublisher() { this(10_000); }
    public InMemoryAuditEventPublisher(int capacity) {
        if (capacity < 1) throw new IllegalArgumentException("capacity must be positive");
        this.capacity = capacity;
    }
    @Override public synchronized void publish(AuditEvent event) {
        if (event == null) return;
        if (events.size() == capacity) events.removeFirst();
        events.addLast(event);
    }
    public synchronized List<AuditEvent> getEvents() { return List.copyOf(events); }
    public synchronized void clear() { events.clear(); }
    public synchronized int size() { return events.size(); }
}
