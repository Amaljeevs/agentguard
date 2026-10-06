package io.agentguard.core.identity;

import io.agentguard.core.model.AgentIdentity;
import java.util.Optional;

/**
 * Strategy interface for resolving the active AgentIdentity from the current execution context.
 * Implementations may resolve from Spring SecurityContext, JWT Bearer tokens, SPIFFE Workload IDs,
 * or asynchronous task metadata.
 */
public interface AgentIdentityResolver {

    /**
     * Resolves the active agent identity, if present.
     *
     * @return an Optional containing the verified AgentIdentity, or empty if no agent is authenticated
     */
    Optional<AgentIdentity> resolveCurrentIdentity();
}
