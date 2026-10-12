package io.agentguard.audit.model;

import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.model.*;
import io.agentguard.core.security.RequestFingerprint;
import java.time.Instant;
import java.util.*;

/** Immutable authorization evidence. Parameters are sanitized; publishers should prefer argumentsHash. */
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
    Map<String, Object> metadata,
    List<String> delegationChain,
    String argumentsHash,
    Optional<String> policyVersion,
    Optional<String> policyHash,
    RiskLevel riskLevel,
    String traceId,
    Optional<String> approvalRequestId
) {
    /** Original constructor retained for source compatibility. */
    public AuditEvent(String eventId, Instant timestamp, String agentId, AgentType agentType, Set<String> roles,
                      String action, Map<String, Object> parameters, String resourceType, String resourceId,
                      String environment, Decision decision, String reason, Optional<String> matchedPolicyName,
                      Optional<String> matchedRuleId, Optional<String> delegatedBy, Optional<String> sessionId,
                      Map<String, Object> metadata) {
        this(eventId, timestamp, agentId, agentType, roles, action, parameters, resourceType, resourceId,
            environment, decision, reason, matchedPolicyName, matchedRuleId, delegatedBy, sessionId, metadata,
            delegatedBy.map(List::of).orElseGet(List::of), RequestFingerprint.argumentsHash(parameters),
            Optional.empty(), Optional.empty(), decision == Decision.ALLOW ? RiskLevel.LOW : RiskLevel.MEDIUM,
            eventId, Optional.empty());
    }

    public AuditEvent {
        Objects.requireNonNull(eventId, "eventId"); Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(agentId, "agentId"); Objects.requireNonNull(agentType, "agentType");
        Objects.requireNonNull(action, "action"); Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(reason, "reason");
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        parameters = parameters == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
        matchedPolicyName = matchedPolicyName == null ? Optional.empty() : matchedPolicyName;
        matchedRuleId = matchedRuleId == null ? Optional.empty() : matchedRuleId;
        delegatedBy = delegatedBy == null ? Optional.empty() : delegatedBy;
        sessionId = sessionId == null ? Optional.empty() : sessionId;
        metadata = metadata == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(metadata));
        delegationChain = delegationChain == null ? List.of() : List.copyOf(delegationChain);
        Objects.requireNonNull(argumentsHash, "argumentsHash");
        policyVersion = policyVersion == null ? Optional.empty() : policyVersion;
        policyHash = policyHash == null ? Optional.empty() : policyHash;
        riskLevel = riskLevel == null ? RiskLevel.MEDIUM : riskLevel;
        Objects.requireNonNull(traceId, "traceId");
        approvalRequestId = approvalRequestId == null ? Optional.empty() : approvalRequestId;
    }

    public static AuditEvent from(AuthorizationRequest request, AuthorizationDecision decision,
                                  ParameterSanitizer sanitizer) {
        Objects.requireNonNull(request, "request"); Objects.requireNonNull(decision, "decision");
        ParameterSanitizer active = sanitizer != null ? sanitizer : new DefaultParameterSanitizer();
        AgentIdentity subject = request.subject();
        return new AuditEvent(UUID.randomUUID().toString(), decision.evaluatedAt(), subject.agentId(),
            subject.agentType(), subject.roles(), request.action().name(), active.sanitize(request.action().parameters()),
            request.resource().type(), request.resource().id(), request.context().environment(), decision.decision(),
            decision.reason(), decision.matchedPolicyName(), decision.matchedRuleId(), subject.delegatedBy(),
            subject.sessionId(), active.sanitize(request.context().metadata()), subject.delegationChain(),
            RequestFingerprint.argumentsHash(request.action().parameters()), decision.policyVersion(),
            decision.policyHash(), decision.riskLevel(), decision.traceId(), Optional.empty());
    }

    /** Adds trusted lifecycle metadata while retaining the sanitized request snapshot. */
    public AuditEvent lifecycle(String phase, String correlationId, String policyRevision, Map<String, Object> details) {
        var extra = new LinkedHashMap<>(metadata);
        if (details != null) extra.putAll(details);
        extra.put("phase", phase); extra.put("correlationId", correlationId); extra.put("policyRevision", policyRevision);
        Optional<String> approval = approvalRequestId;
        if (phase != null && phase.startsWith("APPROVAL_")) approval = Optional.ofNullable(correlationId);
        Object explicit = extra.get("approvalRequestId");
        if (explicit instanceof String id && !id.isBlank()) approval = Optional.of(id);
        return new AuditEvent(UUID.randomUUID().toString(), Instant.now(), agentId, agentType, roles, action,
            parameters, resourceType, resourceId, environment, decision, reason, matchedPolicyName, matchedRuleId,
            delegatedBy, sessionId, extra, delegationChain, argumentsHash, policyVersion, policyHash, riskLevel,
            traceId, approval);
    }
}
