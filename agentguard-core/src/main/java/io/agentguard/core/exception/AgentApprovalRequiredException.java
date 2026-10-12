package io.agentguard.core.exception;

import io.agentguard.core.model.AuthorizationDecision;
import java.util.Optional;

/**
 * Thrown when an agent authorization request triggers an APPROVAL_REQUIRED policy rule.
 * Intercepted by MCP / tool executors to halt autonomous execution and dispatch approval workflows.
 */
public class AgentApprovalRequiredException extends AgentGuardException {

    private final AuthorizationDecision decision;
    private final Optional<String> approvalRequestId;

    public AgentApprovalRequiredException(String message, AuthorizationDecision decision) {
        this(message, decision, Optional.empty());
    }

    public AgentApprovalRequiredException(String message, AuthorizationDecision decision, Optional<String> approvalRequestId) {
        super(message);
        this.decision = decision;
        this.approvalRequestId = approvalRequestId == null ? Optional.empty() : approvalRequestId;
    }

    public AuthorizationDecision getDecision() {
        return decision;
    }

    public Optional<String> getApprovalRequestId() { return approvalRequestId; }
}
