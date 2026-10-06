package io.agentguard.core.exception;

import io.agentguard.core.model.AuthorizationDecision;

/**
 * Thrown when an agent authorization request evaluates to DENY.
 */
public class AgentAccessDeniedException extends AgentGuardException {

    private final AuthorizationDecision decision;

    public AgentAccessDeniedException(String message, AuthorizationDecision decision) {
        super(message);
        this.decision = decision;
    }

    public AgentAccessDeniedException(String message) {
        super(message);
        this.decision = AuthorizationDecision.deny(message);
    }

    public AuthorizationDecision getDecision() {
        return decision;
    }
}
