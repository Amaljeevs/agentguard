package io.agentguard.audit.model;

import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AgentType;
import io.agentguard.core.model.AuthorizationDecision;
import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.core.model.Decision;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Immutable audit record representing an evaluated authorization decision.
 * All sensitive action parameters are sanitized prior to event construction.
 */
public record AuditEvent(
    String eventId,
    Instant timestamp,
    String agentId,
    AgentType agentType,
    Set<String> roles,
    String action,
    Map<String, Object> parameters,
    String resourceType,
    String resourceId,
    String environment,
    Decision decision,
    String reason,
    Optional<String> matchedPolicyName,
    Optional<String> matchedRuleId,
    Optional<String> delegatedBy,
    Optional<String> sessionId,
    Map<String, Object> metadata
) {
    public AuditEvent {
        Objects.requireNonNull(eventId, "eventId must not be null");
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(agentType, "agentType must not be null");
        Objects.requireNonNull(action, "action must not be null");
        Objects.requireNonNull(decision, "decision must not be null");
        Objects.requireNonNull(reason, "reason must not be null");

        roles = roles == null ? Set.of() : Set.copyOf(roles);
        parameters = parameters == null ? Map.of() : Map.copyOf(parameters);
        matchedPolicyName = matchedPolicyName == null ? Optional.empty() : matchedPolicyName;
        matchedRuleId = matchedRuleId == null ? Optional.empty() : matchedRuleId;
        delegatedBy = delegatedBy == null ? Optional.empty() : delegatedBy;
        sessionId = sessionId == null ? Optional.empty() : sessionId;
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
    }

    /**
     * Constructs an AuditEvent from an AuthorizationRequest and its resulting AuthorizationDecision,
     * applying the provided ParameterSanitizer.
     */
    public static AuditEvent from(
        AuthorizationRequest request,
        AuthorizationDecision decision,
        ParameterSanitizer sanitizer
    ) {
        Objects.requireNonNull(request, "request must not be null");
        Objects.requireNonNull(decision, "decision must not be null");
        ParameterSanitizer activeSanitizer = sanitizer != null ? sanitizer : new DefaultParameterSanitizer();

        AgentIdentity subject = request.subject();
        Map<String, Object> sanitizedParams = activeSanitizer.sanitize(request.action().parameters());

        return new AuditEvent(
            UUID.randomUUID().toString(),
            decision.evaluatedAt() != null ? decision.evaluatedAt() : Instant.now(),
            subject != null ? subject.agentId() : "ANONYMOUS",
            subject != null ? subject.agentType() : AgentType.WORKER,
            subject != null ? subject.roles() : Set.of(),
            request.action().name(),
            sanitizedParams,
            request.resource().type(),
            request.resource().id(),
            request.context().environment(),
            decision.decision(),
            decision.reason(),
            decision.matchedPolicyName(),
            decision.matchedRuleId(),
            subject != null ? subject.delegatedBy() : Optional.empty(),
            subject != null ? subject.sessionId() : Optional.empty(),
            request.context().metadata()
        );
    }
}
