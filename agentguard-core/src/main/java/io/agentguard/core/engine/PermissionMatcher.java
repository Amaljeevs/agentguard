package io.agentguard.core.engine;

/**
 * Strategy interface for matching permission strings against granted permission patterns.
 * Supports exact matching and hierarchical dot/wildcard patterns (e.g. {@code database.*}, {@code *.read}, {@code *}).
 */
public interface PermissionMatcher {

    /**
     * Determines whether the given granted pattern satisfies the requested action.
     *
     * @param pattern the granted permission pattern (e.g. "database.*" or "*")
     * @param action the requested action name (e.g. "database.query")
     * @return true if the pattern grants the action, false otherwise
     */
    boolean matches(String pattern, String action);
}
