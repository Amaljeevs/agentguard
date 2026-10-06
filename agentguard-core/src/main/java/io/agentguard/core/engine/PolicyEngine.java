package io.agentguard.core.engine;

import io.agentguard.core.model.AuthorizationDecision;
import io.agentguard.core.model.AuthorizationRequest;

/**
 * The Policy Decision Point (PDP) contract for AgentGuard.
 * Evaluates an incoming authorization request against compiled security policies.
 */
public interface PolicyEngine {

    /**
     * Evaluates an authorization request and returns a deterministic decision (ALLOW, DENY, APPROVAL_REQUIRED).
     *
     * @param request the authorization request containing subject, action, resource, and context
     * @return the authorization decision with explanatory reason and rule provenance
     */
    AuthorizationDecision evaluate(AuthorizationRequest request);
}
