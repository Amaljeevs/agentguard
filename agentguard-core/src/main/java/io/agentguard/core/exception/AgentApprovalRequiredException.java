package io.agentguard.core.exception;

import io.agentguard.core.model.AuthorizationDecision;

/**
 * Thrown when an agent authorization request triggers an APPROVAL_REQUIRED policy rule.
 * Intercepted by MCP / tool executors to halt autonomous execution and dispatch approval workflows.
 */
public class AgentApprovalRequiredException extends AgentGuardException {

    private final AuthorizationDecision decision;

    public AgentApprovalRequiredException(String message, AuthorizationDecision decision) {
        super(message);
        this.decision = decision;
    }

    public AuthorizationDecision getDecision() {
        return decision;
    }
}
