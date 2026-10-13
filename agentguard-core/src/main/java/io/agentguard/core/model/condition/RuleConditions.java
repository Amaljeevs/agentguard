package io.agentguard.core.model.condition;

import io.agentguard.core.model.AuthorizationRequest;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable representation of contextual conditions configured on a policy rule.
 * Evaluates arguments, subject attributes, resource tags, environment, tenant, and context.
 */
public record RuleConditions(
    Map<String, Map<ConditionOperator, Object>> argumentConditions,
    Map<String, Map<ConditionOperator, Object>> subjectAttributeConditions,
    Map<String, Map<ConditionOperator, Object>> subjectDirectConditions,
    Map<String, Map<ConditionOperator, Object>> resourceTagConditions,
    Map<String, Map<ConditionOperator, Object>> resourceDirectConditions,
    Map<ConditionOperator, Object> environmentConditions,
    Map<ConditionOperator, Object> tenantConditions,
    Map<String, Map<ConditionOperator, Object>> contextConditions
) {
    public static final RuleConditions EMPTY = new RuleConditions(
        Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of()
    );

    public RuleConditions {
        argumentConditions = copyNested(argumentConditions);
        subjectAttributeConditions = copyNested(subjectAttributeConditions);
        subjectDirectConditions = copyNested(subjectDirectConditions);
        resourceTagConditions = copyNested(resourceTagConditions);
        resourceDirectConditions = copyNested(resourceDirectConditions);
        environmentConditions = environmentConditions == null ? Map.of() : Map.copyOf(environmentConditions);
        tenantConditions = tenantConditions == null ? Map.of() : Map.copyOf(tenantConditions);
        contextConditions = copyNested(contextConditions);
    }

    public boolean isEmpty() {
        return argumentConditions.isEmpty()
            && subjectAttributeConditions.isEmpty()
            && subjectDirectConditions.isEmpty()
            && resourceTagConditions.isEmpty()
            && resourceDirectConditions.isEmpty()
            && environmentConditions.isEmpty()
            && tenantConditions.isEmpty()
            && contextConditions.isEmpty();
    }

    /**
     * Deterministically tests all conditions against the given authorization request.
     * All specified conditions must evaluate to true (logical AND).
     */
    public boolean matches(AuthorizationRequest request) {
        if (request == null) return false;

        // 1. Environment conditions
        if (!environmentConditions.isEmpty()) {
            String actualEnv = request.context().environment();
            for (var entry : environmentConditions.entrySet()) {
                if (!ConditionEvaluator.evaluate(entry.getKey(), actualEnv, entry.getValue())) {
                    return false;
                }
            }
        }

        // 2. Tenant conditions
        if (!tenantConditions.isEmpty()) {
            String actualTenant = request.subject().tenantId().orElse(null);
            for (var entry : tenantConditions.entrySet()) {
                if (!ConditionEvaluator.evaluate(entry.getKey(), actualTenant, entry.getValue())) {
                    return false;
                }
            }
        }

        // 3. Argument conditions
        if (!argumentConditions.isEmpty()) {
            Map<String, Object> params = request.action().parameters();
            for (var fieldEntry : argumentConditions.entrySet()) {
                String fieldName = fieldEntry.getKey();
                Object actualVal = params != null ? params.get(fieldName) : null;
                for (var opEntry : fieldEntry.getValue().entrySet()) {
                    if (!ConditionEvaluator.evaluate(opEntry.getKey(), actualVal, opEntry.getValue())) {
                        return false;
                    }
                }
            }
        }

        // 4. Subject attribute conditions
        if (!subjectAttributeConditions.isEmpty()) {
            Map<String, Object> attrs = request.subject().attributes();
            for (var attrEntry : subjectAttributeConditions.entrySet()) {
                String attrName = attrEntry.getKey();
                Object actualVal = attrs != null ? attrs.get(attrName) : null;
                for (var opEntry : attrEntry.getValue().entrySet()) {
                    if (!ConditionEvaluator.evaluate(opEntry.getKey(), actualVal, opEntry.getValue())) {
                        return false;
                    }
                }
            }
        }

        // 5. Subject direct conditions (agentId, agentType, tenant)
        if (!subjectDirectConditions.isEmpty()) {
            for (var directEntry : subjectDirectConditions.entrySet()) {
                String field = directEntry.getKey();
                Object actualVal = switch (field.toLowerCase()) {
                    case "agentid" -> request.subject().agentId();
                    case "agenttype" -> request.subject().agentType().name();
                    case "tenant", "tenantid" -> request.subject().tenantId().orElse(null);
                    default -> null;
                };
                for (var opEntry : directEntry.getValue().entrySet()) {
                    if (!ConditionEvaluator.evaluate(opEntry.getKey(), actualVal, opEntry.getValue())) {
                        return false;
                    }
                }
            }
        }

        // 6. Resource tag conditions
        if (!resourceTagConditions.isEmpty()) {
            Map<String, String> tags = request.resource().tags();
            for (var tagEntry : resourceTagConditions.entrySet()) {
                String tagName = tagEntry.getKey();
                Object actualVal = tags != null ? tags.get(tagName) : null;
                for (var opEntry : tagEntry.getValue().entrySet()) {
                    if (!ConditionEvaluator.evaluate(opEntry.getKey(), actualVal, opEntry.getValue())) {
                        return false;
                    }
                }
            }
        }

        // 7. Resource direct conditions (type, id)
        if (!resourceDirectConditions.isEmpty()) {
            for (var directEntry : resourceDirectConditions.entrySet()) {
                String field = directEntry.getKey();
                Object actualVal = switch (field.toLowerCase()) {
                    case "type" -> request.resource().type();
                    case "id" -> request.resource().id();
                    default -> null;
                };
                for (var opEntry : directEntry.getValue().entrySet()) {
                    if (!ConditionEvaluator.evaluate(opEntry.getKey(), actualVal, opEntry.getValue())) {
                        return false;
                    }
                }
            }
        }

        // 8. Context metadata conditions
        if (!contextConditions.isEmpty()) {
            Map<String, Object> metadata = request.context().metadata();
            for (var metaEntry : contextConditions.entrySet()) {
                String key = metaEntry.getKey();
                Object actualVal = metadata != null ? metadata.get(key) : null;
                for (var opEntry : metaEntry.getValue().entrySet()) {
                    if (!ConditionEvaluator.evaluate(opEntry.getKey(), actualVal, opEntry.getValue())) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    private static Map<String, Map<ConditionOperator, Object>> copyNested(
        Map<String, Map<ConditionOperator, Object>> source
    ) {
        if (source == null || source.isEmpty()) return Map.of();
        Map<String, Map<ConditionOperator, Object>> result = new LinkedHashMap<>();
        for (var entry : source.entrySet()) {
            result.put(entry.getKey(), entry.getValue() == null ? Map.of() : Map.copyOf(entry.getValue()));
        }
        return Collections.unmodifiableMap(result);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final Map<String, Map<ConditionOperator, Object>> argumentConditions = new LinkedHashMap<>();
        private final Map<String, Map<ConditionOperator, Object>> subjectAttributeConditions = new LinkedHashMap<>();
        private final Map<String, Map<ConditionOperator, Object>> subjectDirectConditions = new LinkedHashMap<>();
        private final Map<String, Map<ConditionOperator, Object>> resourceTagConditions = new LinkedHashMap<>();
        private final Map<String, Map<ConditionOperator, Object>> resourceDirectConditions = new LinkedHashMap<>();
        private final Map<ConditionOperator, Object> environmentConditions = new LinkedHashMap<>();
        private final Map<ConditionOperator, Object> tenantConditions = new LinkedHashMap<>();
        private final Map<String, Map<ConditionOperator, Object>> contextConditions = new LinkedHashMap<>();

        public Builder argument(String field, ConditionOperator operator, Object expected) {
            argumentConditions.computeIfAbsent(field, k -> new LinkedHashMap<>()).put(operator, expected);
            return this;
        }

        public Builder subjectAttribute(String attribute, ConditionOperator operator, Object expected) {
            subjectAttributeConditions.computeIfAbsent(attribute, k -> new LinkedHashMap<>()).put(operator, expected);
            return this;
        }

        public Builder subjectField(String field, ConditionOperator operator, Object expected) {
            subjectDirectConditions.computeIfAbsent(field, k -> new LinkedHashMap<>()).put(operator, expected);
            return this;
        }

        public Builder resourceTag(String tag, ConditionOperator operator, Object expected) {
            resourceTagConditions.computeIfAbsent(tag, k -> new LinkedHashMap<>()).put(operator, expected);
            return this;
        }

        public Builder resourceField(String field, ConditionOperator operator, Object expected) {
            resourceDirectConditions.computeIfAbsent(field, k -> new LinkedHashMap<>()).put(operator, expected);
            return this;
        }

        public Builder environment(ConditionOperator operator, Object expected) {
            environmentConditions.put(operator, expected);
            return this;
        }

        public Builder tenant(ConditionOperator operator, Object expected) {
            tenantConditions.put(operator, expected);
            return this;
        }

        public Builder context(String key, ConditionOperator operator, Object expected) {
            contextConditions.computeIfAbsent(key, k -> new LinkedHashMap<>()).put(operator, expected);
            return this;
        }

        public RuleConditions build() {
            return new RuleConditions(
                argumentConditions,
                subjectAttributeConditions,
                subjectDirectConditions,
                resourceTagConditions,
                resourceDirectConditions,
                environmentConditions,
                tenantConditions,
                contextConditions
            );
        }
    }
}

