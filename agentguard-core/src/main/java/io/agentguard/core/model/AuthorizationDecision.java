package io.agentguard.core.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Complete, reviewable policy decision returned by the PDP. */
public record AuthorizationDecision(
    Decision decision,
    String reason,
    Optional<String> matchedPolicyName,
    Optional<String> matchedRuleId,
    Instant evaluatedAt,
    Optional<String> policyVersion,
    Optional<String> policyHash,
    RiskLevel riskLevel,
    String traceId
) {
    /** Source-compatible constructor retained for callers constructing the original decision shape. */
    public AuthorizationDecision(Decision decision, String reason, Optional<String> matchedPolicyName,
                                 Optional<String> matchedRuleId, Instant evaluatedAt) {
        this(decision, reason, matchedPolicyName, matchedRuleId, evaluatedAt,
            Optional.empty(), Optional.empty(), defaultRisk(decision), UUID.randomUUID().toString());
    }

    public AuthorizationDecision {
        Objects.requireNonNull(decision, "decision must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        matchedPolicyName = matchedPolicyName == null ? Optional.empty() : matchedPolicyName;
        matchedRuleId = matchedRuleId == null ? Optional.empty() : matchedRuleId;
        Objects.requireNonNull(evaluatedAt, "evaluatedAt must not be null");
        policyVersion = policyVersion == null ? Optional.empty() : policyVersion;
        policyHash = policyHash == null ? Optional.empty() : policyHash;
        riskLevel = riskLevel == null ? defaultRisk(decision) : riskLevel;
        if (traceId == null || traceId.isBlank()) traceId = UUID.randomUUID().toString();
    }

    public Optional<String> matchedPolicyId() { return matchedPolicyName; }
    public boolean isAllowed() { return decision == Decision.ALLOW; }
    public boolean isDenied() { return decision == Decision.DENY; }
    public boolean isApprovalRequired() { return decision == Decision.APPROVAL_REQUIRED; }

    public static AuthorizationDecision allow(String reason, String policy) { return allow(reason, policy, null); }
    public static AuthorizationDecision allow(String reason, String policy, String rule) {
        return basic(Decision.ALLOW, reason, policy, rule);
    }
    public static AuthorizationDecision deny(String reason) { return basic(Decision.DENY, reason, null, null); }
    public static AuthorizationDecision deny(String reason, String policy, String rule) {
        return basic(Decision.DENY, reason, policy, rule);
    }
    public static AuthorizationDecision requireApproval(String reason, String policy, String rule) {
        return basic(Decision.APPROVAL_REQUIRED, reason, policy, rule);
    }

    public static AuthorizationDecision detailed(Decision decision, String reason, String policyId,
                                                  String ruleId, String policyVersion, String policyHash,
                                                  RiskLevel risk, String traceId, Instant evaluatedAt) {
        return new AuthorizationDecision(decision, reason, Optional.ofNullable(policyId), Optional.ofNullable(ruleId),
            evaluatedAt, Optional.ofNullable(policyVersion), Optional.ofNullable(policyHash), risk, traceId);
    }

    private static AuthorizationDecision basic(Decision decision, String reason, String policy, String rule) {
        return new AuthorizationDecision(decision, reason, Optional.ofNullable(policy), Optional.ofNullable(rule),
            Instant.now(), Optional.empty(), Optional.empty(), defaultRisk(decision), UUID.randomUUID().toString());
    }
    private static RiskLevel defaultRisk(Decision decision) {
        return decision == Decision.APPROVAL_REQUIRED ? RiskLevel.HIGH
            : decision == Decision.DENY ? RiskLevel.MEDIUM : RiskLevel.LOW;
    }
}
