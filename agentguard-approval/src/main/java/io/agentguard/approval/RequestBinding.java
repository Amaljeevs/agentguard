package io.agentguard.approval;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.core.model.*;
import java.time.Instant;
import java.util.*;
import java.security.MessageDigest;

/** Canonical, lossless JSON-compatible argument snapshots. Unsupported objects fail closed. */
final class RequestBinding {
    private static final ObjectMapper JSON = new ObjectMapper();
    private RequestBinding() {}

    static AuthorizationRequest snapshot(AuthorizationRequest request, Instant now) {
        var identity = request.subject();
        var frozenIdentity = new AgentIdentity(identity.agentId(), identity.agentType(), identity.roles(), identity.permissions(),
            identity.delegatedBy(), identity.sessionId(), identity.issuedAt(), identity.expiresAt(), freezeMap(identity.attributes()));
        return AuthorizationRequest.of(frozenIdentity, Action.of(request.action().name(), freezeMap(request.action().parameters())),
            request.resource(), new AuthorizationContext(request.context().environment(), now, freezeMap(request.context().metadata())));
    }

    static String digest(AuthorizationRequest request) {
        var subject = request.subject();
        Map<String, Object> data = new TreeMap<>();
        data.put("agentId", subject.agentId()); data.put("agentType", subject.agentType().name());
        data.put("roles", subject.roles().stream().sorted().toList());
        data.put("permissions", subject.permissions().stream().sorted().toList());
        data.put("delegatedBy", subject.delegatedBy().orElse("")); data.put("sessionId", subject.sessionId().orElse(""));
        data.put("issuedAt", subject.issuedAt().toString()); data.put("expiresAt", subject.expiresAt().toString());
        data.put("attributes", freezeMap(subject.attributes()));
        data.put("action", request.action().name()); data.put("parameters", freezeMap(request.action().parameters()));
        data.put("resourceType", request.resource().type()); data.put("resourceId", request.resource().id());
        data.put("tags", new TreeMap<>(request.resource().tags())); data.put("environment", request.context().environment());
        data.put("context", freezeMap(request.context().metadata()));
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(JSON.writeValueAsBytes(data))); }
        catch (Exception failure) { throw new IllegalArgumentException("Cannot bind approval request"); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> freezeMap(Map<String, ?> map) {
        return (Map<String, Object>) freeze(map, new IdentityHashMap<>(), 0);
    }

    private static Object freeze(Object value, IdentityHashMap<Object, Boolean> path, int depth) {
        if (value == null || value instanceof String || value instanceof Boolean || value instanceof Byte
            || value instanceof Short || value instanceof Integer || value instanceof Long
            || value instanceof java.math.BigDecimal || value instanceof java.math.BigInteger) return value;
        if (value instanceof Double number && Double.isFinite(number)) return number;
        if (value instanceof Float number && Float.isFinite(number)) return number;
        if (depth > 32 || path.put(value, true) != null) throw new IllegalArgumentException("Approval arguments exceed depth or contain cycles");
        try {
            if (value instanceof Map<?, ?> map) {
                if (map.size() > 1000) throw new IllegalArgumentException("Too many approval arguments");
                Map<String, Object> copy = new TreeMap<>();
                for (var entry : map.entrySet()) {
                    if (!(entry.getKey() instanceof String key)) throw new IllegalArgumentException("Approval keys must be strings");
                    copy.put(key, freeze(entry.getValue(), path, depth + 1));
                }
                return Collections.unmodifiableMap(copy);
            }
            if (value instanceof List<?> list) {
                if (list.size() > 1000) throw new IllegalArgumentException("Too many approval arguments");
                List<Object> copy = new ArrayList<>();
                for (Object item : list) copy.add(freeze(item, path, depth + 1));
                return Collections.unmodifiableList(copy);
            }
            throw new IllegalArgumentException("Approval arguments must be JSON-compatible values");
        } finally { path.remove(value); }
    }
}
