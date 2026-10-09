package io.agentguard.audit.sanitizer;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.assertj.core.api.Assertions.assertThat;

class StructuredSanitizerTest {
    private final ParameterSanitizer sanitizer = new DefaultParameterSanitizer();
    record Payload(String name, String password, @Sensitive String value) {}
    public static class Bean {
        public String getName() { return "visible"; }
        public String getApiKey() { throw new AssertionError("Sensitive getter must not run"); }
        @Sensitive public String getValue() { return "hidden"; }
    }
    @Test void recordsBeansAndAnnotationsAreSanitizedWithoutInvokingSensitiveGetters() {
        var result = sanitizer.sanitize(Map.of("record", new Payload("visible", "secret", "hidden"), "bean", new Bean()));
        assertThat(result.toString()).doesNotContain("secret", "hidden");
        assertThat(((Map<?, ?>) result.get("record")).get("name")).isEqualTo("visible");
        assertThat(((Map<?, ?>) result.get("record")).get("value")).isEqualTo("[REDACTED]");
        assertThat(((Map<?, ?>) result.get("bean")).get("name")).isEqualTo("visible");
        assertThat(((Map<?, ?>) result.get("bean")).get("value")).isEqualTo("[REDACTED]");
    }
    @Test void nullsArraysAndCyclesAreHandledWithoutLeaking() {
        Map<String, Object> values = new HashMap<>();
        values.put("nullable", null); values.put("array", new Object[]{null, Map.of("token", "hidden")});
        values.put("cycle", values);
        var result = sanitizer.sanitize(values);
        assertThat(result).containsEntry("nullable", null).containsEntry("cycle", "[REDACTED]");
        assertThat(result.toString()).doesNotContain("hidden");
        assertThat((List<?>) result.get("array")).hasSize(2);
    }
    @Test void unknownObjectsNeverUseToString() {
        var result = sanitizer.sanitize(Map.of("unknown", new Object() {
            @Override public String toString() { throw new AssertionError("Do not call toString"); }
        }));
        assertThat(result).containsEntry("unknown", "[REDACTED]");
    }
}
