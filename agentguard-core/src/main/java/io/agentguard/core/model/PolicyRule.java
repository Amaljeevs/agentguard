package io.agentguard.core.model;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Granular contextual rule targeting specific roles, actions, resources, and environments.
 * Used for ABAC, environmental constraints, explicit denies, and approval triggers.
 */
public record PolicyRule(
    String id,
    Optional<String> description,
    RuleEffect effect,
    Set<String> targetRoles,
    Set<String> targetActions,
    Optional<String> resourceType,
    Optional<String> resourceId,
    Set<String> environments
) {
    public PolicyRule {
        Objects.requireNonNull(id, "Rule id must not be null");
        Objects.requireNonNull(effect, "Rule effect must not be null");
        description = description == null ? Optional.empty() : description;
        targetRoles = targetRoles == null ? Set.of() : Set.copyOf(targetRoles);
        targetActions = targetActions == null ? Set.of() : Set.copyOf(targetActions);
        resourceType = resourceType == null ? Optional.empty() : resourceType;
        resourceId = resourceId == null ? Optional.empty() : resourceId;
        environments = environments == null ? Set.of() : Set.copyOf(environments);
    }

    public static Builder builder(String id, RuleEffect effect) {
        return new Builder(id, effect);
    }

    public static final class Builder {
        private final String id;
        private final RuleEffect effect;
        private String description;
        private Set<String> targetRoles = Set.of();
        private Set<String> targetActions = Set.of();
        private String resourceType;
        private String resourceId;
        private Set<String> environments = Set.of();

        public Builder(String id, RuleEffect effect) {
            this.id = id;
            this.effect = effect;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder targetRoles(Set<String> targetRoles) {
            this.targetRoles = targetRoles;
            return this;
        }

        public Builder targetActions(Set<String> targetActions) {
            this.targetActions = targetActions;
            return this;
        }

        public Builder resourceType(String resourceType) {
            this.resourceType = resourceType;
            return this;
        }

        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        public Builder environments(Set<String> environments) {
            this.environments = environments;
            return this;
        }

        public PolicyRule build() {
            return new PolicyRule(
                id,
                Optional.ofNullable(description),
                effect,
                targetRoles,
                targetActions,
                Optional.ofNullable(resourceType),
                Optional.ofNullable(resourceId),
                environments
            );
        }
    }
}
