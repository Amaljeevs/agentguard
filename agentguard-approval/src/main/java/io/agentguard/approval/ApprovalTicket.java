package io.agentguard.approval;

import java.time.Instant;
import java.util.Objects;

/** Stores cryptographic fingerprints and lifecycle evidence, never raw arguments or credentials. */
public record ApprovalTicket(
    String id,
    String subjectId,
    String action,
    String resourceType,
    String resourceId,
    String requestHash,
    String argumentsHash,
    String policyRevision,
    String environment,
    String traceId,
    Instant createdAt,
    Instant expiresAt,
    State state,
    String decidedBy
) {
    public enum State {
        APPROVAL_REQUIRED, APPROVED, DENIED, EXPIRED, CONSUMED,
        /** @deprecated use APPROVAL_REQUIRED */ @Deprecated PENDING,
        /** @deprecated use DENIED */ @Deprecated REJECTED
    }

    public ApprovalTicket {
        requireText(id, "id"); requireText(subjectId, "subjectId"); requireText(action, "action");
        requireText(resourceType, "resourceType"); requireText(resourceId, "resourceId");
        requireText(requestHash, "requestHash"); requireText(argumentsHash, "argumentsHash");
        requireText(policyRevision, "policyRevision"); requireText(environment, "environment");
        requireText(traceId, "traceId");
        Objects.requireNonNull(createdAt, "createdAt"); Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(state, "state");
        if (expiresAt.isBefore(createdAt)) throw new IllegalArgumentException("expiresAt cannot precede createdAt");
    }

    /** Original constructor retained for source compatibility. */
    public ApprovalTicket(String id, String subjectId, String binding, String policyRevision,
                          String environment, Instant createdAt, Instant expiresAt, State state, String approvedBy) {
        this(id, subjectId, "unknown", "unknown", "unknown", binding, "unknown", policyRevision,
            environment, id, createdAt, expiresAt, state, approvedBy);
    }

    /** @deprecated use {@link #requestHash()}. */
    @Deprecated public String binding() { return requestHash; }
    /** @deprecated use {@link #decidedBy()}. */
    @Deprecated public String approvedBy() { return decidedBy; }

    public ApprovalTicket withState(State next, String actor) {
        return new ApprovalTicket(id, subjectId, action, resourceType, resourceId, requestHash, argumentsHash,
            policyRevision, environment, traceId, createdAt, expiresAt, next, actor);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
    }
}
