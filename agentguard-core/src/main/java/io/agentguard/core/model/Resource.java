package io.agentguard.core.model;

import java.util.Map;
import java.util.Objects;

/**
 * Represents the target object, dataset, or infrastructure entity being accessed.
 * Examples: {@code type="database", id="customer-db"}, {@code type="k8s_cluster", id="prod-cluster"}.
 */
public record Resource(
    String type,
    String id,
    Map<String, String> tags
) {
    public Resource {
        Objects.requireNonNull(type, "Resource type must not be null");
        Objects.requireNonNull(id, "Resource id must not be null");
        tags = tags == null ? Map.of() : Map.copyOf(tags);
    }

    public static Resource of(String type, String id) {
        return new Resource(type, id, Map.of());
    }

    public static Resource of(String type, String id, Map<String, String> tags) {
        return new Resource(type, id, tags);
    }
}
