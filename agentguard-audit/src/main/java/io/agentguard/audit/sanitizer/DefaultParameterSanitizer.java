package io.agentguard.audit.sanitizer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Standard implementation of {@link ParameterSanitizer}.
 * Recursively inspects parameter maps and lists, replacing any values associated with
 * sensitive keys with a designated mask token (default: {@code "[REDACTED]"}).
 */
public class DefaultParameterSanitizer implements ParameterSanitizer {

    public static final String DEFAULT_MASK = "[REDACTED]";

    public static final Set<String> DEFAULT_SENSITIVE_KEYS = Set.of(
        "password",
        "secret",
        "token",
        "apikey",
        "key",
        "authorization",
        "credentials",
        "bearer",
        "private",
        "cert",
        "certificate",
        "ssn",
        "creditcard"
    );

    private final Set<String> normalizedSensitiveKeys;
    private final String maskToken;

    public DefaultParameterSanitizer() {
        this(DEFAULT_SENSITIVE_KEYS, DEFAULT_MASK);
    }

    public DefaultParameterSanitizer(Set<String> sensitiveKeys, String maskToken) {
        Objects.requireNonNull(sensitiveKeys, "sensitiveKeys must not be null");
        this.maskToken = maskToken != null ? maskToken : DEFAULT_MASK;
        this.normalizedSensitiveKeys = sensitiveKeys.stream()
            .filter(Objects::nonNull)
            .map(k -> k.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", ""))
            .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public Map<String, Object> sanitize(Map<String, Object> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            return Map.of();
        }
        return sanitizeMap(parameters);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> sanitizeMap(Map<String, Object> map) {
        Map<String, Object> sanitized = new HashMap<>();

        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (isSensitiveKey(key)) {
                sanitized.put(key, maskToken);
            } else if (value instanceof Map<?, ?> nestedMap) {
                sanitized.put(key, sanitizeMap((Map<String, Object>) nestedMap));
            } else if (value instanceof List<?> nestedList) {
                sanitized.put(key, sanitizeList(nestedList));
            } else {
                sanitized.put(key, value);
            }
        }

        return Map.copyOf(sanitized);
    }

    @SuppressWarnings("unchecked")
    private List<Object> sanitizeList(List<?> list) {
        List<Object> sanitized = new ArrayList<>(list.size());

        for (Object item : list) {
            if (item instanceof Map<?, ?> nestedMap) {
                sanitized.add(sanitizeMap((Map<String, Object>) nestedMap));
            } else if (item instanceof List<?> nestedList) {
                sanitized.add(sanitizeList(nestedList));
            } else {
                sanitized.add(item);
            }
        }

        return List.copyOf(sanitized);
    }

    private boolean isSensitiveKey(String key) {
        if (key == null) {
            return false;
        }
        String normalized = key.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        for (String sensitive : normalizedSensitiveKeys) {
            if (normalized.contains(sensitive)) {
                return true;
            }
        }
        return false;
    }

    public String getMaskToken() {
        return maskToken;
    }
}
