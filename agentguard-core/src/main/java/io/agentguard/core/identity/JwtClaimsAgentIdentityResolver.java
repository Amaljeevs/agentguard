package io.agentguard.core.identity;

import io.agentguard.core.exception.AgentAuthenticationException;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AgentType;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

/** Maps already-verified JWT claims into an immutable AgentGuard identity. */
public final class JwtClaimsAgentIdentityResolver implements AgentIdentityResolver {
    private static final Set<String> SAFE_ATTRIBUTES = Set.of("sub", "client_id", "tenant", "tid", "iss", "jti");
    private final VerifiedClaimsSource source;
    private final Clock clock;

    public JwtClaimsAgentIdentityResolver(VerifiedClaimsSource source) { this(source, Clock.systemUTC()); }
    public JwtClaimsAgentIdentityResolver(VerifiedClaimsSource source, Clock clock) {
        this.source = Objects.requireNonNull(source, "source");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override public Optional<AgentIdentity> resolveCurrentIdentity() {
        Optional<VerifiedClaims> current = source.current();
        if (current == null || current.isEmpty()) return Optional.empty();
        return Optional.of(resolve(current.get()));
    }

    public AgentIdentity resolve(VerifiedClaims verified) {
        Objects.requireNonNull(verified, "verified");
        Map<String, Object> claims = verified.claims();
        String subject = optionalString(claims, "sub");
        String clientId = optionalString(claims, "client_id");
        String agentId = clientId != null ? clientId : subject;
        if (agentId == null) throw malformed("sub or client_id is required");
        Instant issuedAt = instant(claims.get("iat"), "iat", true);
        Instant expiresAt = instant(claims.get("exp"), "exp", false);
        Instant now = clock.instant();
        if (!now.isBefore(expiresAt)) throw malformed("token is expired");
        if (issuedAt.isAfter(now.plusSeconds(60))) throw malformed("iat is in the future");

        Set<String> roles = strings(claims.get("roles"), "roles");
        Object realmAccess = claims.get("realm_access");
        if (realmAccess instanceof Map<?, ?> realm && realm.get("roles") != null) {
            var combined = new LinkedHashSet<>(roles);
            combined.addAll(strings(realm.get("roles"), "realm_access.roles"));
            roles = Set.copyOf(combined);
        } else if (realmAccess != null && !(realmAccess instanceof Map<?, ?>)) {
            throw malformed("realm_access must be an object");
        }
        Set<String> scopes = new LinkedHashSet<>(strings(claims.get("scp"), "scp"));
        scopes.addAll(strings(claims.get("scope"), "scope"));
        List<String> chain = chain(claims);
        String tenant = first(optionalString(claims, "tenant"), optionalString(claims, "tid"));

        var builder = AgentIdentity.builder().agentId(agentId).agentType(AgentType.AUTONOMOUS)
            .roles(roles).permissions(scopes).delegationChain(chain).issuedAt(issuedAt).expiresAt(expiresAt)
            .attribute("issuer", verified.issuer());
        if (tenant != null) builder.tenantId(tenant);
        SAFE_ATTRIBUTES.forEach(key -> {
            Object value = claims.get(key);
            if (value instanceof String safe && !safe.isBlank()) builder.attribute(key, safe);
        });
        String session = first(optionalString(claims, "sid"), optionalString(claims, "jti"));
        if (session != null) builder.sessionId(session);
        return builder.build();
    }

    private List<String> chain(Map<String, Object> claims) {
        List<String> result = new ArrayList<>(listStrings(claims.get("delegation_chain"), "delegation_chain"));
        Object actor = claims.containsKey("actor") ? claims.get("actor") : claims.get("act");
        String actorId = null;
        if (actor instanceof String value) actorId = nonBlank(value, "actor");
        else if (actor instanceof Map<?, ?> map) {
            Object candidate = map.get("client_id") != null ? map.get("client_id") : map.get("sub");
            if (candidate != null) actorId = nonBlankType(candidate, "actor.sub/client_id");
        } else if (actor != null) throw malformed("actor must be a string or object");
        if (actorId != null && (result.isEmpty() || !result.getLast().equals(actorId))) result.add(actorId);
        if (new HashSet<>(result).size() != result.size()) throw malformed("delegation chain contains a cycle");
        return List.copyOf(result);
    }

    private static Set<String> strings(Object value, String claim) {
        if (value == null) return Set.of();
        if (value instanceof String text) {
            if (text.isBlank()) return Set.of();
            return Set.copyOf(Arrays.asList(text.trim().split("\\s+")));
        }
        return Set.copyOf(listStrings(value, claim));
    }
    private static List<String> listStrings(Object value, String claim) {
        if (value == null) return List.of();
        if (!(value instanceof Collection<?> collection)) throw malformed(claim + " must be a string or string array");
        var result = new ArrayList<String>();
        for (Object entry : collection) result.add(nonBlankType(entry, claim));
        return result;
    }
    private static Instant instant(Object value, String claim, boolean defaultEpoch) {
        if (value == null && defaultEpoch) return Instant.EPOCH;
        if (value instanceof Instant instant) return instant;
        if (value instanceof Number number) return Instant.ofEpochSecond(number.longValue());
        if (value instanceof String text) {
            try { return text.matches("^-?\\d+$") ? Instant.ofEpochSecond(Long.parseLong(text)) : Instant.parse(text); }
            catch (RuntimeException invalid) { throw malformed(claim + " is malformed"); }
        }
        throw malformed(claim + " is required and must be a numeric date");
    }
    private static String optionalString(Map<String, Object> claims, String key) {
        Object value = claims.get(key);
        return value == null ? null : nonBlankType(value, key);
    }
    private static String nonBlankType(Object value, String claim) {
        if (!(value instanceof String text)) throw malformed(claim + " must be a string");
        return nonBlank(text, claim);
    }
    private static String nonBlank(String text, String claim) {
        if (text.isBlank()) throw malformed(claim + " must not be blank");
        return text;
    }
    private static String first(String first, String second) { return first != null ? first : second; }
    private static AgentAuthenticationException malformed(String reason) {
        return new AgentAuthenticationException("Malformed verified JWT claims: " + reason);
    }
}
