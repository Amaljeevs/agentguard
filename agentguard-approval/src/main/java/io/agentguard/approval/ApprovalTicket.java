package io.agentguard.approval;

import java.time.Instant;

/** Stores a digest, not raw arguments or credentials. Possession of an ID is not authorization. */
public record ApprovalTicket(String id, String subjectId, String binding, String policyRevision,
                             String environment, Instant createdAt, Instant expiresAt, State state, String approvedBy) {
    public enum State { PENDING, APPROVED, CONSUMED, REJECTED }
    public ApprovalTicket withState(State next, String actor) {
        return new ApprovalTicket(id, subjectId, binding, policyRevision, environment, createdAt, expiresAt, next, actor);
    }
}
