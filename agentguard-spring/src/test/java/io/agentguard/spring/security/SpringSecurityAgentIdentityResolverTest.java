package io.agentguard.spring.security;

import io.agentguard.core.model.AgentIdentity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.time.Instant;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SpringSecurityAgentIdentityResolver Context Bridge Tests")
class SpringSecurityAgentIdentityResolverTest {

    private final SpringSecurityAgentIdentityResolver resolver = new SpringSecurityAgentIdentityResolver();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Should return empty when no SecurityContext authentication exists")
    void shouldReturnEmptyWhenUnauthenticated() {
        SecurityContextHolder.clearContext();
        Optional<AgentIdentity> identity = resolver.resolveCurrentIdentity();
        assertThat(identity).isEmpty();
    }

    @Test
    @DisplayName("Should extract agentId and strip ROLE_ prefix from authorities")
    void shouldExtractAgentIdAndRoles() {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
            "coding-agent-17",
            "N/A",
            List.of(new SimpleGrantedAuthority("ROLE_DEVELOPER"), new SimpleGrantedAuthority("ROLE_REVIEWER"))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        Optional<AgentIdentity> identityOpt = resolver.resolveCurrentIdentity();

        assertThat(identityOpt).isPresent();
        AgentIdentity identity = identityOpt.get();
        assertThat(identity.agentId()).isEqualTo("coding-agent-17");
        assertThat(identity.roles()).containsExactlyInAnyOrder("developer", "reviewer");
    }

    @Test void shouldMapClaimsOnlyAfterSpringHasProducedAuthenticatedJwtToken() {
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("opaque-test-value").header("alg", "RS256")
            .issuer("https://issuer.example").subject("human")
            .issuedAt(now.minusSeconds(10)).expiresAt(now.plusSeconds(300))
            .claim("client_id", "trusted-agent").claim("scope", "orders.read orders.refund")
            .claim("tenant", "tenant-a").claim("actor", Map.of("sub", "orchestrator"))
            .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,
            List.of(new SimpleGrantedAuthority("SCOPE_orders.read"))));

        AgentIdentity identity = resolver.resolveCurrentIdentity().orElseThrow();
        assertThat(identity.agentId()).isEqualTo("trusted-agent");
        assertThat(identity.permissions()).containsExactlyInAnyOrder("orders.read", "orders.refund");
        assertThat(identity.tenantId()).contains("tenant-a");
        assertThat(identity.delegationChain()).containsExactly("orchestrator");
    }
}
