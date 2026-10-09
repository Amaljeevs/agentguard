package io.agentguard.core.identity;

import io.agentguard.core.model.AgentIdentity;
import java.util.Optional;

/** Resolves delegation parents from a trusted registry, never from caller-provided attributes. */
@FunctionalInterface
public interface AgentIdentityLookup {
    Optional<AgentIdentity> find(String agentId);
}
