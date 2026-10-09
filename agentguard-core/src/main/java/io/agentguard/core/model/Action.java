package io.agentguard.core.model;

import java.util.Map;
import java.util.Objects;
import java.util.Collections;
import java.util.LinkedHashMap;

/**
 * Represents the target operation or tool call requested by an agent.
 * Examples: {@code database.query}, {@code git.push}, {@code kubernetes.deploy}.
 */
public record Action(
    String name,
    Map<String, Object> parameters
) {
    public Action {
        Objects.requireNonNull(name, "Action name must not be null");
        if (name.isBlank()) {
            throw new IllegalArgumentException("Action name cannot be blank");
        }
        parameters = parameters == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
    }

    public static Action of(String name) {
        return new Action(name, Map.of());
    }

    public static Action of(String name, Map<String, Object> parameters) {
        return new Action(name, parameters);
    }
}
