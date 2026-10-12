package io.agentguard.web.api;

import io.agentguard.core.model.Decision;
import io.agentguard.core.model.RiskLevel;

/** Stable JSON response contract for non-Java clients. */
public record AuthorizationApiResponse(
    Decision decision,
    String reason,
    String matchedPolicy,
    String matchedRule,
    String policyVersion,
    String policyHash,
    RiskLevel risk,
    String approvalRequestId,
    String traceId
) {}
