package io.agentguard.core.model.condition;

import java.util.Optional;

/**
 * Deterministic operator set supported by AgentGuard policy conditions.
 * No arbitrary scripts, expressions, or remote code execution.
 */
public enum ConditionOperator {
    EQUALS("equals"),
    NOT_EQUALS("notEquals"),
    IN("in"),
    NOT_IN("notIn"),
    EXISTS("exists"),
    CONTAINS("contains"),
    GREATER_THAN("greaterThan"),
    GREATER_THAN_OR_EQUAL("greaterThanOrEqual"),
    LESS_THAN("lessThan"),
    LESS_THAN_OR_EQUAL("lessThanOrEqual");

    private final String yamlName;

    ConditionOperator(String yamlName) {
        this.yamlName = yamlName;
    }

    public String yamlName() {
        return yamlName;
    }

    public static Optional<ConditionOperator> fromYaml(String name) {
        if (name == null) return Optional.empty();
        for (ConditionOperator op : values()) {
            if (op.yamlName.equalsIgnoreCase(name) || op.name().equalsIgnoreCase(name)) {
                return Optional.of(op);
            }
        }
        return Optional.empty();
    }
}

