package io.agentguard.core.model;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

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
    }

    /**
     * Checks if this identity is expired relative to the given reference instant.
     */
    public boolean isExpired(Instant now) {
        Objects.requireNonNull(now, "Reference instant must not be null");
        return now.isAfter(expiresAt);
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
