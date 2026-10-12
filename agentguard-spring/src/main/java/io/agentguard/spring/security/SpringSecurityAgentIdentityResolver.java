package io.agentguard.spring.security;

import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AgentType;
import io.agentguard.core.identity.JwtClaimsAgentIdentityResolver;
import io.agentguard.core.identity.VerifiedClaims;
import io.agentguard.core.exception.AgentAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.Map;

/**
 * Bridges Spring Security's {@link SecurityContextHolder} to AgentGuard's {@link AgentIdentity}.
 * Extracts agent identification and granted authorities from the authenticated principal.
 */
public class SpringSecurityAgentIdentityResolver implements AgentIdentityResolver {

    @Override
    public Optional<AgentIdentity> resolveCurrentIdentity() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return Optional.empty();
        }
        if (auth instanceof org.springframework.security.authentication.AnonymousAuthenticationToken) return Optional.empty();
        // A trusted authentication provider may supply an identity with original expiry/delegation.
        if (auth.getPrincipal() instanceof AgentIdentity identity) return Optional.of(identity);
        // Spring's Jwt principal exists only when the application has configured and completed JWT validation.
        if (isSpringJwt(auth.getPrincipal())) return Optional.of(resolveSpringJwt(auth.getPrincipal()));

        String principalName = auth.getName();
        if (principalName == null || principalName.isBlank() || "anonymousUser".equalsIgnoreCase(principalName)) {
            return Optional.empty();
        }

        Set<String> roles = new HashSet<>();
        if (auth.getAuthorities() != null) {
            for (GrantedAuthority ga : auth.getAuthorities()) {
                String authority = ga.getAuthority();
                if (authority != null) {
                    if (authority.startsWith("ROLE_")) {
                        authority = authority.substring(5);
                    }
                    roles.add(authority.toLowerCase(Locale.ROOT));
                }
            }
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plus(1, ChronoUnit.HOURS);

        AgentIdentity identity = AgentIdentity.builder()
            .agentId(principalName)
            .agentType(AgentType.AUTONOMOUS)
            .roles(roles)
            .issuedAt(now)
            .expiresAt(expiresAt)
            .build();

        return Optional.of(identity);
    }

    private static boolean isSpringJwt(Object principal) {
        return principal != null && "org.springframework.security.oauth2.jwt.Jwt".equals(principal.getClass().getName());
    }

    @SuppressWarnings("unchecked")
    private static AgentIdentity resolveSpringJwt(Object jwt) {
        try {
            Object rawClaims = jwt.getClass().getMethod("getClaims").invoke(jwt);
            if (!(rawClaims instanceof Map<?, ?> claims)) {
                throw new AgentAuthenticationException("Verified JWT claims are unavailable");
            }
            Object issuer = claims.get("iss");
            if (!(issuer instanceof String text) || text.isBlank()) {
                throw new AgentAuthenticationException("Verified JWT issuer is required");
            }
            var verified = new VerifiedClaims(text, (Map<String, Object>) claims, Instant.now());
            return new JwtClaimsAgentIdentityResolver(() -> Optional.of(verified)).resolveCurrentIdentity().orElseThrow();
        } catch (AgentAuthenticationException failure) {
            throw failure;
        } catch (ReflectiveOperationException | ClassCastException failure) {
            throw new AgentAuthenticationException("Verified JWT claims could not be resolved");
        }
    }
}
