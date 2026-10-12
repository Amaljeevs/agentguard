package io.agentguard.web.api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.*;

/** Language-neutral request. Principal is an assertion checked against authenticated server context. */
@JsonIgnoreProperties(ignoreUnknown = false)
public record AuthorizationApiRequest(
    String principal,
    String action,
    ApiResource resource,
    Map<String, Object> arguments,
    Map<String, Object> context
) {
    public AuthorizationApiRequest {
        if (action == null || action.isBlank()) throw new IllegalArgumentException("action is required");
        Objects.requireNonNull(resource, "resource is required");
        arguments = immutable(arguments);
        context = immutable(context);
    }

    private static Map<String, Object> immutable(Map<String, Object> value) {
        return value == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(value));
    }

    @JsonIgnoreProperties(ignoreUnknown = false)
    public record ApiResource(String type, String id, Map<String, String> tags) {
        public ApiResource {
            if (type == null || type.isBlank() || id == null || id.isBlank()) {
                throw new IllegalArgumentException("resource type and id are required");
            }
            tags = tags == null ? Map.of() : Map.copyOf(tags);
        }
    }
}
