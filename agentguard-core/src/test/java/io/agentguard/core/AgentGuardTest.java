package io.agentguard.core;

import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.exception.AgentAuthenticationException;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class AgentGuardTest {
    private final AgentIdentity forgedAdmin = AgentIdentity.builder().agentId("payload-admin").permission("*").build();
    private final AgentIdentity verifiedAgent = AgentIdentity.builder().agentId("verified-agent").permission("orders.read").build();
    private final AuthorizationRequest proposed = AuthorizationRequest.of(forgedAdmin, Action.of("secrets.delete"),
        Resource.of("secret", "1"), AuthorizationContext.of("production"));

    @Test void resolverBackedFacadeIgnoresPayloadIdentityAndRoles() {
        var guard = new AgentGuard(new DefaultPolicyEngine(PolicySet.builder("test", "1").build()),
            () -> Optional.of(verifiedAgent));
        assertThat(guard.authorize(proposed).isDenied()).isTrue();
    }

    @Test void missingVerifiedIdentityFailsBeforePolicyEvaluation() {
        var guard = new AgentGuard(new DefaultPolicyEngine(PolicySet.builder("test", "1").build()), Optional::empty);
        assertThatThrownBy(() -> guard.authorize(proposed)).isInstanceOf(AgentAuthenticationException.class);
    }
}
