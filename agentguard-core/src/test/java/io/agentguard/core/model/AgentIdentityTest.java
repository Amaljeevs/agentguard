package io.agentguard.core.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("AgentIdentity Domain Model Tests")
class AgentIdentityTest {

    @Test
    @DisplayName("Should create valid agent identity with builder")
    void shouldCreateValidIdentity() {
        Instant now = Instant.now();
        Instant expiry = now.plus(2, ChronoUnit.HOURS);

        AgentIdentity identity = AgentIdentity.builder()
            .agentId("coding-agent-17")
            .agentType(AgentType.AUTONOMOUS)
            .role("developer")
            .role("code-reviewer")
            .permission("git.read")
            .delegatedBy("user-42")
            .sessionId("sess-99")
            .issuedAt(now)
            .expiresAt(expiry)
            .attribute("team", "platform-eng")
            .build();

        assertThat(identity.agentId()).isEqualTo("coding-agent-17");
        assertThat(identity.agentType()).isEqualTo(AgentType.AUTONOMOUS);
        assertThat(identity.roles()).containsExactlyInAnyOrder("developer", "code-reviewer");
        assertThat(identity.permissions()).containsExactly("git.read");
        assertThat(identity.delegatedBy()).contains("user-42");
        assertThat(identity.sessionId()).contains("sess-99");
        assertThat(identity.attributes()).containsEntry("team", "platform-eng");
        assertThat(identity.isExpired(now.plus(1, ChronoUnit.HOURS))).isFalse();
        assertThat(identity.isExpired(now.plus(3, ChronoUnit.HOURS))).isTrue();
    }

    @Test
    @DisplayName("Should throw exception if expiresAt is before issuedAt")
    void shouldThrowIfExpiresAtBeforeIssuedAt() {
        Instant now = Instant.now();
        Instant past = now.minus(1, ChronoUnit.HOURS);

        assertThatThrownBy(() ->
            AgentIdentity.builder()
                .agentId("bad-agent")
                .issuedAt(now)
                .expiresAt(past)
                .build()
        ).isInstanceOf(IllegalArgumentException.class)
         .hasMessageContaining("expiresAt cannot be earlier than issuedAt");
    }

    @Test
    @DisplayName("Should enforce immutability of roles and permissions sets")
    void shouldEnforceImmutability() {
        AgentIdentity identity = AgentIdentity.builder()
            .agentId("agent-1")
            .role("admin")
            .build();

        Set<String> roles = identity.roles();
        assertThatThrownBy(() -> roles.add("hacker"))
            .isInstanceOf(UnsupportedOperationException.class);
    }
}
