package io.agentguard.spring.security;

import io.agentguard.core.identity.AgentIdentityResolver;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AgentType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

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
}
