package io.agentguard.core.model;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.List;

/**
 * Language-neutral security principal representing an AI agent.
 * Holds verified identification, assigned roles, explicit permissions, delegation provenance,
 * and temporal validity boundaries.
 */
public record AgentIdentity(
    String agentId,
    AgentType agentType,
    Set<String> roles,
    Set<String> permissions,
    Optional<String> delegatedBy,
    Optional<String> sessionId,
    Instant issuedAt,
    Instant expiresAt,
    Map<String, Object> attributes
) {
    public static final String DELEGATION_CHAIN_ATTRIBUTE = "agentguard.delegationChain";
    public static final String TENANT_ATTRIBUTE = "tenant";
    public AgentIdentity {
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(agentType, "agentType must not be null");
        Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");

        if (expiresAt.isBefore(issuedAt)) {
            throw new IllegalArgumentException("expiresAt cannot be earlier than issuedAt");
        }

        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        delegatedBy = delegatedBy == null ? Optional.empty() : delegatedBy;
        sessionId = sessionId == null ? Optional.empty() : sessionId;
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
        Object chainValue = attributes.get(DELEGATION_CHAIN_ATTRIBUTE);
        if (chainValue != null) {
            if (!(chainValue instanceof List<?> chain) || chain.stream().anyMatch(item -> !(item instanceof String text) || text.isBlank())) {
                throw new IllegalArgumentException("delegation chain must be a list of non-blank strings");
            }
            List<String> ids = chain.stream().map(String.class::cast).toList();
            if (new HashSet<>(ids).size() != ids.size()) throw new IllegalArgumentException("delegation chain contains a cycle");
            if (!ids.isEmpty()) delegatedBy = Optional.of(ids.getLast());
        }
    }

    /**
     * Checks if this identity is expired relative to the given reference instant.
     */
    public boolean isExpired(Instant now) {
        Objects.requireNonNull(now, "Reference instant must not be null");
        return !now.isBefore(expiresAt);
    }

    /** Verified ancestor IDs ordered from root authority to immediate delegator. */
    public List<String> delegationChain() {
        Object value = attributes.get(DELEGATION_CHAIN_ATTRIBUTE);
        if (value instanceof List<?> list) {
            return list.stream().map(String.class::cast).toList();
        }
        return delegatedBy.map(List::of).orElseGet(List::of);
    }

    public Optional<String> tenantId() {
        Object value = attributes.get(TENANT_ATTRIBUTE);
        return value instanceof String tenant && !tenant.isBlank() ? Optional.of(tenant) : Optional.empty();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String agentId;
        private AgentType agentType = AgentType.AUTONOMOUS;
        private final Set<String> roles = new HashSet<>();
        private final Set<String> permissions = new HashSet<>();
        private String delegatedBy;
        private String sessionId;
        private Instant issuedAt = Instant.now();
        private Instant expiresAt = Instant.now().plusSeconds(3600);
        private final Map<String, Object> attributes = new HashMap<>();

        public Builder agentId(String agentId) {
            this.agentId = agentId;
            return this;
        }

        public Builder agentType(AgentType agentType) {
            this.agentType = agentType;
            return this;
        }

        public Builder roles(Set<String> roles) {
            if (roles != null) {
                this.roles.addAll(roles);
            }
            return this;
        }

        public Builder role(String role) {
            if (role != null) {
                this.roles.add(role);
            }
            return this;
        }

        public Builder permissions(Set<String> permissions) {
            if (permissions != null) {
                this.permissions.addAll(permissions);
            }
            return this;
        }

        public Builder permission(String permission) {
            if (permission != null) {
                this.permissions.add(permission);
            }
            return this;
        }

        public Builder delegatedBy(String delegatedBy) {
            this.delegatedBy = delegatedBy;
            return this;
        }

        public Builder delegationChain(List<String> chain) {
            if (chain == null || chain.isEmpty()) {
                attributes.remove(DELEGATION_CHAIN_ATTRIBUTE);
                delegatedBy = null;
                return this;
            }
            List<String> copy = chain.stream()
                .map(value -> Objects.requireNonNull(value, "delegation chain entry"))
                .map(String::trim).toList();
            if (copy.stream().anyMatch(String::isBlank) || new HashSet<>(copy).size() != copy.size()) {
                throw new IllegalArgumentException("delegation chain must contain unique non-blank IDs");
            }
            attributes.put(DELEGATION_CHAIN_ATTRIBUTE, copy);
            delegatedBy = copy.getLast();
            return this;
        }

        public Builder tenantId(String tenantId) {
            if (tenantId != null && !tenantId.isBlank()) attributes.put(TENANT_ATTRIBUTE, tenantId);
            return this;
        }

        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Builder issuedAt(Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder attribute(String key, Object value) {
            this.attributes.put(key, value);
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            if (attributes != null) {
                this.attributes.putAll(attributes);
            }
            return this;
        }

        public AgentIdentity build() {
            return new AgentIdentity(
                agentId,
                agentType,
                roles,
                permissions,
                Optional.ofNullable(delegatedBy),
                Optional.ofNullable(sessionId),
                issuedAt,
                expiresAt,
                attributes
            );
        }
    }
}
