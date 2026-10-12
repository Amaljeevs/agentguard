package io.agentguard.core.identity;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Claims produced only after an upstream JWT/OIDC verifier validates signature, issuer and audience. */
public record VerifiedClaims(String issuer, Map<String, Object> claims, Instant verifiedAt) {
    public VerifiedClaims {
        if (issuer == null || issuer.isBlank()) throw new IllegalArgumentException("verified issuer is required");
        claims = Map.copyOf(new LinkedHashMap<>(Objects.requireNonNull(claims, "claims")));
        Objects.requireNonNull(verifiedAt, "verifiedAt");
    }
}
