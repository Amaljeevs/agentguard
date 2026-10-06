package io.agentguard.core.engine;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("DefaultPermissionMatcher Hierarchical Wildcard Tests")
class DefaultPermissionMatcherTest {

    private DefaultPermissionMatcher matcher;

    @BeforeEach
    void setUp() {
        matcher = new DefaultPermissionMatcher();
    }

    @ParameterizedTest(name = "Pattern ''{0}'' matching ''{1}'' should be {2}")
    @CsvSource({
        "git.read, git.read, true",
        "git.read, git.write, false",
        "*, database.query, true",
        "*, any.nested.action.here, true",
        "database.*, database.query, true",
        "database.*, database.schema.migrate, true",
        "database.*, logs.read, false",
        "*.read, git.read, true",
        "*.read, logs.read, true",
        "*.read, git.write, false",
        "kubernetes.*.deploy, kubernetes.cluster1.deploy, true",
        "kubernetes.*.deploy, kubernetes.cluster1.read, false"
    })
    void testPatternMatches(String pattern, String action, boolean expected) {
        assertThat(matcher.matches(pattern, action)).isEqualTo(expected);
    }

    @Test
    @DisplayName("Should handle null or empty inputs safely without throwing")
    void shouldHandleNullOrEmptyInputs() {
        assertThat(matcher.matches(null, "git.read")).isFalse();
        assertThat(matcher.matches("git.read", null)).isFalse();
        assertThat(matcher.matches("", "git.read")).isFalse();
        assertThat(matcher.matches("git.read", "")).isFalse();
    }
}
