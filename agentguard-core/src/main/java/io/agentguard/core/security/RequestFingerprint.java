package io.agentguard.core.security;

import io.agentguard.core.model.AuthorizationRequest;
import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.temporal.TemporalAccessor;
import java.util.*;

/** Canonical SHA-256 fingerprints for JSON-compatible requests and arguments. */
public final class RequestFingerprint {
    private static final int MAX_DEPTH = 32;
    private static final int MAX_ITEMS = 1_000;

    private RequestFingerprint() {}

    public static String argumentsHash(Map<String, ?> arguments) {
        return hash(arguments == null ? Map.of() : arguments);
    }

    /** Excludes evaluation time so the same action can be matched at approval execution time. */
    public static String requestHash(AuthorizationRequest request) {
        Objects.requireNonNull(request, "request");
        var subject = request.subject();
        Map<String, Object> canonical = new TreeMap<>();
        canonical.put("agentId", subject.agentId());
        canonical.put("agentType", subject.agentType().name());
        canonical.put("roles", subject.roles().stream().sorted().toList());
        canonical.put("permissions", subject.permissions().stream().sorted().toList());
        canonical.put("delegationChain", subject.delegationChain());
        canonical.put("sessionId", subject.sessionId().orElse(""));
        canonical.put("issuedAt", subject.issuedAt().toString());
        canonical.put("expiresAt", subject.expiresAt().toString());
        canonical.put("attributes", subject.attributes());
        canonical.put("action", request.action().name());
        canonical.put("arguments", request.action().parameters());
        canonical.put("resourceType", request.resource().type());
        canonical.put("resourceId", request.resource().id());
        canonical.put("resourceTags", new TreeMap<>(request.resource().tags()));
        canonical.put("environment", request.context().environment());
        canonical.put("context", request.context().metadata());
        return hash(canonical);
    }

    private static String hash(Object value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            append(digest, value, new IdentityHashMap<>(), 0);
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static void append(MessageDigest digest, Object value,
                               IdentityHashMap<Object, Boolean> path, int depth) {
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("Fingerprint input exceeds maximum depth");
        if (value == null) { token(digest, "null", ""); return; }
        if (value instanceof String || value instanceof Character || value instanceof UUID
            || value instanceof Enum<?> || value instanceof TemporalAccessor) {
            token(digest, "string", value instanceof Enum<?> e ? e.name() : value.toString()); return;
        }
        if (value instanceof Boolean bool) { token(digest, "boolean", bool.toString()); return; }
        if (value instanceof Number number) {
            try { token(digest, "number", new BigDecimal(number.toString()).stripTrailingZeros().toPlainString()); }
            catch (NumberFormatException invalid) { throw new IllegalArgumentException("Non-finite numbers cannot be fingerprinted"); }
            return;
        }
        if (value instanceof Optional<?> optional) {
            token(digest, "optional", optional.isPresent() ? "present" : "empty");
            optional.ifPresent(item -> append(digest, item, path, depth + 1));
            return;
        }
        if (path.put(value, true) != null) throw new IllegalArgumentException("Fingerprint input contains a cycle");
        try {
            if (value instanceof Map<?, ?> map) {
                if (map.size() > MAX_ITEMS) throw new IllegalArgumentException("Fingerprint input has too many entries");
                token(digest, "map", Integer.toString(map.size()));
                var sorted = new TreeMap<String, Object>();
                for (var entry : map.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) throw new IllegalArgumentException("Fingerprint keys must be strings");
                    sorted.put(key, entry.getValue());
                }
                sorted.forEach((key, item) -> { token(digest, "key", key); append(digest, item, path, depth + 1); });
                return;
            }
            if (value instanceof Iterable<?> iterable) {
                var copy = new ArrayList<>();
                for (Object item : iterable) {
                    if (copy.size() >= MAX_ITEMS) throw new IllegalArgumentException("Fingerprint input has too many items");
                    copy.add(item);
                }
                token(digest, "list", Integer.toString(copy.size()));
                copy.forEach(item -> append(digest, item, path, depth + 1));
                return;
            }
            if (value.getClass().isArray()) {
                int length = Array.getLength(value);
                if (length > MAX_ITEMS) throw new IllegalArgumentException("Fingerprint input has too many items");
                token(digest, "list", Integer.toString(length));
                for (int i = 0; i < length; i++) append(digest, Array.get(value, i), path, depth + 1);
                return;
            }
            if (value.getClass().isRecord()) {
                var components = value.getClass().getRecordComponents();
                token(digest, "record", value.getClass().getName());
                token(digest, "fields", Integer.toString(components.length));
                for (var component : components) {
                    token(digest, "key", component.getName());
                    try {
                        var accessor = component.getAccessor();
                        if (!accessor.canAccess(value) && !accessor.trySetAccessible()) {
                            throw new IllegalArgumentException("Record accessor is not accessible");
                        }
                        append(digest, accessor.invoke(value), path, depth + 1);
                    }
                    catch (ReflectiveOperationException failure) {
                        throw new IllegalArgumentException("Record value cannot be fingerprinted", failure);
                    }
                }
                return;
            }
            throw new IllegalArgumentException("Fingerprint values must be JSON-compatible");
        } finally {
            path.remove(value);
        }
    }

    private static void token(MessageDigest digest, String type, String value) {
        bytes(digest, type.getBytes(StandardCharsets.UTF_8));
        bytes(digest, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void bytes(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(4).putInt(value.length).array());
        digest.update(value);
    }
}
