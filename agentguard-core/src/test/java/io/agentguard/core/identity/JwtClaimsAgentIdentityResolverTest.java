package io.agentguard.core.identity;

import io.agentguard.core.exception.AgentAuthenticationException;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class JwtClaimsAgentIdentityResolverTest {
    private final Instant now = Instant.parse("2026-01-01T00:00:00Z");
    private final Clock clock = Clock.fixed(now, ZoneOffset.UTC);

    @Test void mapsOnlyVerifiedProviderClaimsIncludingActorTenantScopesAndChain() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "human-7"); claims.put("client_id", "deploy-agent"); claims.put("tenant", "tenant-a");
        claims.put("iat", now.minusSeconds(30).getEpochSecond()); claims.put("exp", now.plusSeconds(300).getEpochSecond());
        claims.put("scope", "kubernetes.read kubernetes.deploy"); claims.put("roles", List.of("deployer"));
        claims.put("delegation_chain", List.of("human-7")); claims.put("actor", Map.of("sub", "orchestrator"));
        var verified = new VerifiedClaims("https://issuer.example", claims, now);
        var resolver = new JwtClaimsAgentIdentityResolver(() -> Optional.of(verified), clock);

        var identity = resolver.resolveCurrentIdentity().orElseThrow();
        assertThat(identity.agentId()).isEqualTo("deploy-agent");
        assertThat(identity.roles()).containsExactly("deployer");
        assertThat(identity.permissions()).containsExactlyInAnyOrder("kubernetes.read", "kubernetes.deploy");
        assertThat(identity.tenantId()).contains("tenant-a");
        assertThat(identity.delegationChain()).containsExactly("human-7", "orchestrator");
        assertThat(identity.delegatedBy()).contains("orchestrator");
    }

    @Test void malformedOrExpiredClaimsFailClosed() {
        assertThatThrownBy(() -> resolve(Map.of("sub", "a", "exp", "bad")))
            .isInstanceOf(AgentAuthenticationException.class).hasMessageContaining("exp");
        assertThatThrownBy(() -> resolve(Map.of("sub", "a", "exp", now.plusSeconds(30).getEpochSecond(), "roles", 7)))
            .isInstanceOf(AgentAuthenticationException.class).hasMessageContaining("roles");
        assertThatThrownBy(() -> resolve(Map.of("sub", "a", "exp", now.minusSeconds(1).getEpochSecond())))
            .isInstanceOf(AgentAuthenticationException.class).hasMessageContaining("expired");
        assertThatThrownBy(() -> resolve(Map.of("sub", "a", "exp", now.plusSeconds(30).getEpochSecond(),
            "delegation_chain", List.of("parent", "parent"))))
            .isInstanceOf(AgentAuthenticationException.class).hasMessageContaining("cycle");
    }

    @Test void standardActClaimIsAcceptedAsDelegationActor() {
        var identity = new JwtClaimsAgentIdentityResolver(() -> Optional.empty(), clock).resolve(new VerifiedClaims(
            "issuer", Map.of("sub", "agent", "exp", now.plusSeconds(30).getEpochSecond(),
                "act", Map.of("client_id", "orchestrator")), now));
        assertThat(identity.delegationChain()).containsExactly("orchestrator");
    }

    private void resolve(Map<String, Object> claims) {
        new JwtClaimsAgentIdentityResolver(() -> Optional.empty(), clock)
            .resolve(new VerifiedClaims("issuer", claims, now));
    }
}
