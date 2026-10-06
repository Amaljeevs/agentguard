package io.agentguard.core.model;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Operational execution context for an authorization decision.
 * Contains deployment environment (e.g. "development", "staging", "production"),
 * timestamp, and supplemental environmental or network metadata.
 */
public record AuthorizationContext(
    String environment,
    Instant timestamp,
    Map<String, Object> metadata
) {
    public AuthorizationContext {
        Objects.requireNonNull(environment, "environment must not be null");
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
    }

    public static AuthorizationContext of(String environment) {
        return new AuthorizationContext(environment, Instant.now(), Map.of());
    }

    public static AuthorizationContext of(String environment, Map<String, Object> metadata) {
        return new AuthorizationContext(environment, Instant.now(), metadata);
    }
}
