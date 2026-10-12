package io.agentguard.core.identity;

import java.net.URI;
import java.time.Instant;
import java.util.*;

/**
 * Represents a verified SPIFFE Secure Workload Identity Document (SVID).
 * Standardized SPIFFE ID format: {@code spiffe://<trust-domain>/<path>}
 */
public record SpiffeSvid(
    String spiffeId,
    Instant issuedAt,
    Instant expiresAt,
    Set<String> roles,
    Set<String> permissions,
    List<String> delegationChain,
    Map<String, String> attributes
) {
    public SpiffeSvid {
        Objects.requireNonNull(spiffeId, "spiffeId must not be null");
        if (!spiffeId.startsWith("spiffe://")) {
            throw new IllegalArgumentException("SPIFFE ID must start with 'spiffe://': " + spiffeId);
        }
        URI uri = URI.create(spiffeId);
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException("SPIFFE ID must specify a trust domain: " + spiffeId);
        }
        if (uri.getPath() == null || uri.getPath().isBlank() || uri.getPath().equals("/")) {
            throw new IllegalArgumentException("SPIFFE ID must specify a workload path: " + spiffeId);
        }
        Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        delegationChain = delegationChain == null ? List.of() : List.copyOf(delegationChain);
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    public static SpiffeSvid of(String spiffeId, Instant issuedAt, Instant expiresAt) {
        return new SpiffeSvid(spiffeId, issuedAt, expiresAt, Set.of(), Set.of(), List.of(), Map.of());
    }

    public String trustDomain() {
        return URI.create(spiffeId).getHost();
    }
}

