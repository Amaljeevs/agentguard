package io.agentguard.mcpdemo;

import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.AgentIdentity;
import org.springframework.context.annotation.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import java.time.Instant;
import java.util.*;

@Configuration(proxyBeanMethods = false)
public class TrustedAgents {
    private final Map<String, AgentIdentity> identities;
    public TrustedAgents() {
        var map = new HashMap<String, AgentIdentity>();
        Instant now = Instant.now();
        for (String user : List.of("developer", "operator", "approver")) {
            map.put(user, AgentIdentity.builder().agentId(user).role(user).issuedAt(now).expiresAt(now.plusSeconds(28800)).build());
        }
        identities = Map.copyOf(map);
    }
    public AgentIdentity resolve(java.security.Principal principal) {
        if (principal == null || !identities.containsKey(principal.getName())) throw new AgentAccessDeniedException("Authenticated agent required");
        return identities.get(principal.getName());
    }
    @Bean BCryptPasswordEncoder encoder() { return new BCryptPasswordEncoder(); }
    @Bean UserDetailsService users(BCryptPasswordEncoder encoder) {
        return new InMemoryUserDetailsManager(identities.keySet().stream().map(name ->
            User.withUsername(name).password(encoder.encode("demo-pass")).roles(name.toUpperCase(Locale.ROOT)).build()).toList());
    }
    @Bean SecurityFilterChain security(HttpSecurity http) throws Exception {
        // HTTP Basic is explicitly supplied on every machine-client request; no browser sessions/cookies.
        // MCP and approval API require JSON + credentials; production deployments should use bearer tokens and TLS.
        return http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).httpBasic(Customizer.withDefaults())
            .csrf(csrf -> csrf.ignoringRequestMatchers("/mcp", "/api/**")).build();
    }
}
