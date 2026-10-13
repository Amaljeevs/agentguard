package io.agentguard.core.model.condition;

import java.math.BigDecimal;
import java.util.Collection;
import java.util.Objects;

/**
 * Deterministic, safe evaluator for condition operators.
 * Evaluates numeric, string, boolean, collection, and presence invariants without
 * scripting, reflection, or SpEL.
 */
public final class ConditionEvaluator {

    private ConditionEvaluator() {}

    /**
     * Evaluates a single condition operator against an actual value.
     *
     * @param operator the operator to test
     * @param actual the value resolved from the request (may be null)
     * @param expected the expected value defined in policy
     * @return true if the condition is satisfied, false otherwise
     */
    public static boolean evaluate(ConditionOperator operator, Object actual, Object expected) {
        if (operator == null) {
            return false;
        }

        return switch (operator) {
            case EXISTS -> evaluateExists(actual, expected);
            case EQUALS -> evaluateEquals(actual, expected);
            case NOT_EQUALS -> !evaluateEquals(actual, expected);
            case IN -> evaluateIn(actual, expected);
            case NOT_IN -> evaluateNotIn(actual, expected);
            case CONTAINS -> evaluateContains(actual, expected);
            case GREATER_THAN -> compareNumeric(actual, expected) > 0;
            case GREATER_THAN_OR_EQUAL -> {
                int cmp = compareNumeric(actual, expected);
                yield cmp >= 0 && cmp != Integer.MIN_VALUE;
            }
            case LESS_THAN -> {
                int cmp = compareNumeric(actual, expected);
                yield cmp < 0 && cmp != Integer.MIN_VALUE;
            }
            case LESS_THAN_OR_EQUAL -> {
                int cmp = compareNumeric(actual, expected);
                yield cmp <= 0 && cmp != Integer.MIN_VALUE;
            }
        };
    }

    private static boolean evaluateExists(Object actual, Object expected) {
        boolean shouldExist = true;
        if (expected instanceof Boolean b) {
            shouldExist = b;
        } else if (expected instanceof String s) {
            shouldExist = Boolean.parseBoolean(s);
        }
        return shouldExist ? (actual != null) : (actual == null);
    }

    public static boolean evaluateEquals(Object actual, Object expected) {
        if (actual == null && expected == null) return true;
        if (actual == null || expected == null) return false;

        // Try numeric comparison
        BigDecimal numActual = parseBigDecimal(actual);
        BigDecimal numExpected = parseBigDecimal(expected);
        if (numActual != null && numExpected != null) {
            return numActual.compareTo(numExpected) == 0;
        }

        // Try boolean comparison
        if (actual instanceof Boolean || expected instanceof Boolean) {
            Boolean b1 = actual instanceof Boolean b ? b : Boolean.valueOf(actual.toString());
            Boolean b2 = expected instanceof Boolean b ? b : Boolean.valueOf(expected.toString());
            return Objects.equals(b1, b2);
        }

        // String / Object equality
        return Objects.equals(actual.toString(), expected.toString());
    }

    private static boolean evaluateIn(Object actual, Object expected) {
        if (actual == null || expected == null) return false;
        if (expected instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (evaluateEquals(actual, item)) {
                    return true;
                }
            }
            return false;
        }
        if (expected.getClass().isArray()) {
            int len = java.lang.reflect.Array.getLength(expected);
            for (int i = 0; i < len; i++) {
                if (evaluateEquals(actual, java.lang.reflect.Array.get(expected, i))) {
                    return true;
                }
            }
            return false;
        }
        return evaluateEquals(actual, expected);
    }

    private static boolean evaluateNotIn(Object actual, Object expected) {
        if (actual == null) return true;
        if (expected == null) return true;
        return !evaluateIn(actual, expected);
    }

    private static boolean evaluateContains(Object actual, Object expected) {
        if (actual == null || expected == null) return false;
        if (actual instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (evaluateEquals(item, expected)) {
                    return true;
                }
            }
            return false;
        }
        if (actual.getClass().isArray()) {
            int len = java.lang.reflect.Array.getLength(actual);
            for (int i = 0; i < len; i++) {
                if (evaluateEquals(java.lang.reflect.Array.get(actual, i), expected)) {
                    return true;
                }
            }
            return false;
        }
        if (actual instanceof String s) {
            return s.contains(expected.toString());
        }
        return false;
    }

    /**
     * Compares two objects numerically.
     * Returns Integer.MIN_VALUE if either cannot be parsed as a number.
     */
    private static int compareNumeric(Object actual, Object expected) {
        if (actual == null || expected == null) return Integer.MIN_VALUE;
        BigDecimal numActual = parseBigDecimal(actual);
        BigDecimal numExpected = parseBigDecimal(expected);
        if (numActual == null || numExpected == null) {
            return Integer.MIN_VALUE;
        }
        return numActual.compareTo(numExpected);
    }

    private static BigDecimal parseBigDecimal(Object value) {
        if (value == null) return null;
        if (value instanceof BigDecimal bd) return bd;
        if (value instanceof Number n) {
            try {
                return new BigDecimal(n.toString());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        if (value instanceof String s && !s.isBlank()) {
            try {
                return new BigDecimal(s.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }
}

