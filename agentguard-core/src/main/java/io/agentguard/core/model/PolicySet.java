package io.agentguard.core.model;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable compiled policy graph comprising RBAC role definitions
 * and fine-grained contextual policy rules.
 */
public record PolicySet(
    String name,
    String version,
    Map<String, RoleDefinition> roles,
    List<PolicyRule> rules
) {
    public PolicySet {
        Objects.requireNonNull(name, "PolicySet name must not be null");
        Objects.requireNonNull(version, "PolicySet version must not be null");
        roles = roles == null ? Map.of() : Map.copyOf(roles);
        rules = rules == null ? List.of() : List.copyOf(rules);
    }

    public Optional<RoleDefinition> getRole(String roleName) {
        return Optional.ofNullable(roles.get(roleName));
    }

    public static Builder builder(String name, String version) {
        return new Builder(name, version);
    }

    public static final class Builder {
        private final String name;
        private final String version;
        private Map<String, RoleDefinition> roles = Map.of();
        private List<PolicyRule> rules = List.of();

        public Builder(String name, String version) {
            this.name = name;
            this.version = version;
        }

        public Builder roles(Map<String, RoleDefinition> roles) {
            this.roles = roles;
            return this;
        }

        public Builder rules(List<PolicyRule> rules) {
            this.rules = rules;
            return this;
        }

        public PolicySet build() {
            return new PolicySet(name, version, roles, rules);
        }
    }
}
