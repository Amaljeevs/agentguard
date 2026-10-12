package io.agentguard.core;

import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.AgentAuthenticationException;
import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.core.model.AuthorizationDecision;
import io.agentguard.core.model.AuthorizationRequest;
import java.util.Objects;
import java.util.Optional;

/** Small programmatic facade for applications that do not use Spring interception. */
public final class AgentGuard {
    private final PolicyEngine policyEngine;
    private final Optional<AgentIdentityResolver> identities;

    /** For trusted in-process requests whose identity was already resolved by the application. */
    public AgentGuard(PolicyEngine policyEngine) {
        this(policyEngine, null);
    }

    /** Rebinds every request to the current verified identity and ignores caller-supplied authority. */
    public AgentGuard(PolicyEngine policyEngine, AgentIdentityResolver identities) {
        this.policyEngine = Objects.requireNonNull(policyEngine, "policyEngine");
        this.identities = Optional.ofNullable(identities);
    }

    public AuthorizationDecision authorize(AuthorizationRequest request) {
        Objects.requireNonNull(request, "request");
        if (identities.isEmpty()) return policyEngine.evaluate(request);
        var verified = identities.get().resolveCurrentIdentity()
            .orElseThrow(() -> new AgentAuthenticationException("Verified agent identity is required"));
        var trusted = AuthorizationRequest.of(verified, request.action(), request.resource(), request.context());
        return policyEngine.evaluate(trusted);
    }

    public String policyRevision() {
        return policyEngine.revision();
    }
}
