package io.agentguard.core.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Result returned by the Policy Decision Point (PDP).
 * Fully describes the decision, explanatory reason, matched policy/rule, and evaluation timestamp.
 */
public record AuthorizationDecision(
    Decision decision,
    String reason,
    Optional<String> matchedPolicyName,
    Optional<String> matchedRuleId,
    Instant evaluatedAt
) {
    public AuthorizationDecision {
        Objects.requireNonNull(decision, "decision must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(matchedPolicyName, "matchedPolicyName must not be null");
        Objects.requireNonNull(matchedRuleId, "matchedRuleId must not be null");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt must not be null");
    }

    public boolean isAllowed() {
        return decision == Decision.ALLOW;
    }

    public boolean isDenied() {
        return decision == Decision.DENY;
    }

    public boolean isApprovalRequired() {
        return decision == Decision.APPROVAL_REQUIRED;
    }

    public static AuthorizationDecision allow(String reason, String matchedPolicyName) {
        return new AuthorizationDecision(
            Decision.ALLOW,
            reason,
            Optional.ofNullable(matchedPolicyName),
            Optional.empty(),
            Instant.now()
        );
    }

    public static AuthorizationDecision allow(String reason, String matchedPolicyName, String matchedRuleId) {
        return new AuthorizationDecision(
            Decision.ALLOW,
            reason,
            Optional.ofNullable(matchedPolicyName),
            Optional.ofNullable(matchedRuleId),
            Instant.now()
        );
    }

    public static AuthorizationDecision deny(String reason) {
        return new AuthorizationDecision(
            Decision.DENY,
            reason,
            Optional.empty(),
            Optional.empty(),
            Instant.now()
        );
    }

    public static AuthorizationDecision deny(String reason, String matchedPolicyName, String matchedRuleId) {
        return new AuthorizationDecision(
            Decision.DENY,
            reason,
            Optional.ofNullable(matchedPolicyName),
            Optional.ofNullable(matchedRuleId),
            Instant.now()
        );
    }

    public static AuthorizationDecision requireApproval(String reason, String matchedPolicyName, String matchedRuleId) {
        return new AuthorizationDecision(
            Decision.APPROVAL_REQUIRED,
            reason,
            Optional.ofNullable(matchedPolicyName),
            Optional.ofNullable(matchedRuleId),
            Instant.now()
        );
    }
}
