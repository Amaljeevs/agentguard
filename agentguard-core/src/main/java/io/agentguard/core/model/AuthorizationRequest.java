package io.agentguard.core.model;

import java.util.Objects;

/**
 * Domain request sent to the AgentGuard Policy Engine (PDP).
 * Encapsulates Subject + Action + Resource + Context.
 */
public record AuthorizationRequest(
    AgentIdentity subject,
    Action action,
    Resource resource,
    AuthorizationContext context
) {
    public AuthorizationRequest {
        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(action, "action must not be null");
        Objects.requireNonNull(resource, "resource must not be null");
        Objects.requireNonNull(context, "context must not be null");
    }

    public static AuthorizationRequest of(
        AgentIdentity subject,
        Action action,
        Resource resource,
        AuthorizationContext context
    ) {
        return new AuthorizationRequest(subject, action, resource, context);
    }
}
