package io.agentguard.approval;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.UnaryOperator;

/** Single-process reference store. Use a shared transactional store for clustered deployments. */
public final class InMemoryApprovalStore implements ApprovalStore {
    private final ConcurrentHashMap<String, ApprovalTicket> tickets = new ConcurrentHashMap<>();
    private final int capacity;
    public InMemoryApprovalStore() { this(10_000); }
    public InMemoryApprovalStore(int capacity) {
        if (capacity < 1) throw new IllegalArgumentException("capacity must be positive");
        this.capacity = capacity;
    }
    @Override public synchronized void create(ApprovalTicket ticket) {
        if (tickets.size() >= capacity) throw new IllegalStateException("Approval store capacity exceeded");
        if (tickets.putIfAbsent(ticket.id(), ticket) != null) throw new IllegalStateException("Duplicate approval ID");
    }
    @Override public Optional<ApprovalTicket> find(String id) { return Optional.ofNullable(tickets.get(id)); }
    @Override public ApprovalTicket update(String id, UnaryOperator<ApprovalTicket> transition) {
        return tickets.compute(id, (key, current) -> {
            if (current == null) throw new IllegalArgumentException("Unknown approval ID");
            return java.util.Objects.requireNonNull(transition.apply(current));
        });
    }
    public void removeExpired(Instant now) { tickets.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().expiresAt())); }
}
