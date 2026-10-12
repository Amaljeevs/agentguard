package io.agentguard.approval;

import io.agentguard.core.model.*;
import java.time.Instant;
import java.util.*;
import io.agentguard.core.security.RequestFingerprint;

/** Canonical, lossless JSON-compatible argument snapshots. Unsupported objects fail closed. */
final class RequestBinding {
    private RequestBinding() {}

    static AuthorizationRequest snapshot(AuthorizationRequest request, Instant now) {
        var identity = request.subject();
        var frozenIdentity = new AgentIdentity(identity.agentId(), identity.agentType(), identity.roles(), identity.permissions(),
            identity.delegatedBy(), identity.sessionId(), identity.issuedAt(), identity.expiresAt(), freezeMap(identity.attributes()));
        return AuthorizationRequest.of(frozenIdentity, Action.of(request.action().name(), freezeMap(request.action().parameters())),
            request.resource(), new AuthorizationContext(request.context().environment(), now, freezeMap(request.context().metadata())));
    }

    static String digest(AuthorizationRequest request) {
        return RequestFingerprint.requestHash(request);
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
