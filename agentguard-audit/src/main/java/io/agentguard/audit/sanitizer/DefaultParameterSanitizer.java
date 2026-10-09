package io.agentguard.audit.sanitizer;

import java.lang.reflect.Array;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.stream.Collectors;

/** Bounded, cycle-safe structured redaction. Unknown objects are masked, never rendered with toString(). */
public class DefaultParameterSanitizer implements ParameterSanitizer {
    public static final String DEFAULT_MASK = "[REDACTED]";
    public static final Set<String> DEFAULT_SENSITIVE_KEYS = Set.of(
        "password", "secret", "token", "apikey", "key", "authorization", "credentials",
        "bearer", "private", "cert", "certificate", "ssn", "creditcard");
    private static final int MAX_DEPTH = 32;
    private static final int MAX_ITEMS = 1000;
    private final Set<String> normalizedSensitiveKeys;
    private final String maskToken;

    public DefaultParameterSanitizer() { this(DEFAULT_SENSITIVE_KEYS, DEFAULT_MASK); }
    public DefaultParameterSanitizer(Set<String> sensitiveKeys, String maskToken) {
        Objects.requireNonNull(sensitiveKeys, "sensitiveKeys");
        this.maskToken = maskToken == null ? DEFAULT_MASK : maskToken;
        this.normalizedSensitiveKeys = sensitiveKeys.stream().filter(Objects::nonNull)
            .map(DefaultParameterSanitizer::normalize).filter(key -> !key.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> sanitize(Map<String, Object> parameters) {
        if (parameters == null) return Map.of();
        return (Map<String, Object>) value(parameters, new IdentityHashMap<>(), 0);
    }

    private Object value(Object input, IdentityHashMap<Object, Boolean> path, int depth) {
        if (input == null) return null;
        if (input instanceof String || input instanceof Boolean || input instanceof Character
            || input instanceof Byte || input instanceof Short || input instanceof Integer || input instanceof Long
            || input instanceof Float || input instanceof Double || input instanceof java.math.BigDecimal
            || input instanceof java.math.BigInteger) return input;
        if (input instanceof Enum<?> e) return e.name();
        if (input instanceof UUID || input.getClass().getPackageName().equals("java.time")) return input.toString();
        if (depth >= MAX_DEPTH || path.put(input, true) != null) return maskToken;
        try {
            if (input instanceof Optional<?> optional) return value(optional.orElse(null), path, depth + 1);
            if (input instanceof Map<?, ?> map) {
                Map<String, Object> result = new LinkedHashMap<>();
                int count = 0;
                for (var entry : map.entrySet()) {
                    if (++count > MAX_ITEMS) { result.put("[TRUNCATED]", maskToken); break; }
                    if (!(entry.getKey() instanceof String key)) continue;
                    result.put(key, sensitive(key) ? maskToken : value(entry.getValue(), path, depth + 1));
                }
                return Collections.unmodifiableMap(result);
            }
            if (input instanceof Iterable<?> iterable) {
                List<Object> result = new ArrayList<>();
                for (Object item : iterable) {
                    if (result.size() >= MAX_ITEMS) { result.add(maskToken); break; }
                    result.add(value(item, path, depth + 1));
                }
                return Collections.unmodifiableList(result);
            }
            if (input.getClass().isArray()) {
                List<Object> result = new ArrayList<>();
                int length = Math.min(Array.getLength(input), MAX_ITEMS);
                for (int i = 0; i < length; i++) result.add(value(Array.get(input, i), path, depth + 1));
                if (Array.getLength(input) > length) result.add(maskToken);
                return Collections.unmodifiableList(result);
            }
            Map<String, Object> fields = new LinkedHashMap<>();
            if (input.getClass().isRecord()) {
                for (var component : input.getClass().getRecordComponents()) {
                    var accessor = component.getAccessor();
                    fields.put(component.getName(), sensitive(component.getName()) || component.isAnnotationPresent(Sensitive.class)
                        || accessor.isAnnotationPresent(Sensitive.class) ? maskToken : read(input, accessor, path, depth));
                }
            } else {
                // Explicit DTO support: public JavaBean getters. Arbitrary fields/toString are never serialized.
                for (var method : input.getClass().getMethods()) {
                    if (Modifier.isStatic(method.getModifiers()) || method.getParameterCount() != 0
                        || method.getDeclaringClass() == Object.class || method.getReturnType() == void.class) continue;
                    String name = method.getName();
                    String property = name.startsWith("get") && name.length() > 3 ? name.substring(3)
                        : name.startsWith("is") && name.length() > 2 && (method.getReturnType() == boolean.class
                        || method.getReturnType() == Boolean.class) ? name.substring(2) : null;
                    if (property == null) continue;
                    property = Character.toLowerCase(property.charAt(0)) + property.substring(1);
                    fields.put(property, sensitive(property) || method.isAnnotationPresent(Sensitive.class)
                        ? maskToken : read(input, method, path, depth));
                    if (fields.size() >= MAX_ITEMS) break;
                }
            }
            return fields.isEmpty() ? maskToken : Collections.unmodifiableMap(fields);
        } finally { path.remove(input); }
    }

    private Object read(Object owner, java.lang.reflect.Method method, IdentityHashMap<Object, Boolean> path, int depth) {
        try {
            if (!method.canAccess(owner) && !method.trySetAccessible()) return maskToken;
            return value(method.invoke(owner), path, depth + 1);
        } catch (ReflectiveOperationException | RuntimeException failure) { return maskToken; }
    }

    private static String normalize(String key) { return key.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", ""); }
    private boolean sensitive(String key) {
        String normalized = normalize(key);
        return normalizedSensitiveKeys.stream().anyMatch(normalized::contains);
    }
    public String getMaskToken() { return maskToken; }
}
