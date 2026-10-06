package io.agentguard.core.model;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Definition of an RBAC role containing its granted permission patterns.
 */
public record RoleDefinition(
    String name,
    Optional<String> description,
    Set<String> permissions
) {
    public RoleDefinition {
        Objects.requireNonNull(name, "Role name must not be null");
        if (name.isBlank()) {
            throw new IllegalArgumentException("Role name cannot be blank");
        }
        description = description == null ? Optional.empty() : description;
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
    }

    public static RoleDefinition of(String name, Set<String> permissions) {
        return new RoleDefinition(name, Optional.empty(), permissions);
    }

    public static RoleDefinition of(String name, String description, Set<String> permissions) {
        return new RoleDefinition(name, Optional.ofNullable(description), permissions);
    }
}
