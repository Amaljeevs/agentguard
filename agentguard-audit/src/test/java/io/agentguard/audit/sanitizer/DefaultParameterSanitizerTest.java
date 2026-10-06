package io.agentguard.audit.sanitizer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("DefaultParameterSanitizer Sensitive Masking Tests")
class DefaultParameterSanitizerTest {

    private DefaultParameterSanitizer sanitizer;

    @BeforeEach
    void setUp() {
        sanitizer = new DefaultParameterSanitizer();
    }

    @Test
    @DisplayName("Should mask top-level sensitive fields while retaining non-sensitive fields")
    void shouldMaskTopLevelSensitiveFields() {
        Map<String, Object> params = Map.of(
            "username", "admin",
            "password", "SuperSecret123!",
            "apiKey", "sk-live-992834192",
            "query", "SELECT id FROM users;"
        );

        Map<String, Object> sanitized = sanitizer.sanitize(params);

        assertThat(sanitized).containsEntry("username", "admin");
        assertThat(sanitized).containsEntry("query", "SELECT id FROM users;");
        assertThat(sanitized).containsEntry("password", "[REDACTED]");
        assertThat(sanitized).containsEntry("apiKey", "[REDACTED]");
    }

    @Test
    @DisplayName("Should mask case-insensitive variants of sensitive keys (API_KEY, Secret_Token)")
    void shouldMaskCaseInsensitiveVariants() {
        Map<String, Object> params = Map.of(
            "API_KEY", "secret-key-val",
            "AUTH_TOKEN", "bearer-token-val",
            "db_password", "db-pass",
            "table_name", "customers"
        );

        Map<String, Object> sanitized = sanitizer.sanitize(params);

        assertThat(sanitized).containsEntry("table_name", "customers");
        assertThat(sanitized).containsEntry("API_KEY", "[REDACTED]");
        assertThat(sanitized).containsEntry("AUTH_TOKEN", "[REDACTED]");
        assertThat(sanitized).containsEntry("db_password", "[REDACTED]");
    }

    @Test
    @DisplayName("Should mask recursively inside nested maps")
    void shouldMaskInsideNestedMaps() {
        Map<String, Object> nested = Map.of(
            "host", "prod-db.internal",
            "credentials", Map.of(
                "token", "secret-token",
                "cert", "-----BEGIN CERTIFICATE-----"
            )
        );

        Map<String, Object> sanitized = sanitizer.sanitize(nested);

        assertThat(sanitized).containsEntry("host", "prod-db.internal");
        assertThat(sanitized).containsEntry("credentials", "[REDACTED]");
    }

    @Test
    @DisplayName("Should mask recursively inside nested lists of objects")
    void shouldMaskInsideNestedLists() {
        Map<String, Object> params = Map.of(
            "batch", List.of(
                Map.of("user", "alice", "token", "tok-1"),
                Map.of("user", "bob", "password", "pass-2")
            )
        );

        Map<String, Object> sanitized = sanitizer.sanitize(params);

        assertThat(sanitized).containsKey("batch");
        List<?> batch = (List<?>) sanitized.get("batch");
        assertThat(batch).hasSize(2);

        @SuppressWarnings("unchecked")
        Map<String, Object> item0 = (Map<String, Object>) batch.get(0);
        assertThat(item0).containsEntry("user", "alice");
        assertThat(item0).containsEntry("token", "[REDACTED]");
    }

    @Test
    @DisplayName("Should safely handle null or empty parameter maps")
    void shouldHandleNullOrEmpty() {
        assertThat(sanitizer.sanitize(null)).isEmpty();
        assertThat(sanitizer.sanitize(Map.of())).isEmpty();
    }
}
