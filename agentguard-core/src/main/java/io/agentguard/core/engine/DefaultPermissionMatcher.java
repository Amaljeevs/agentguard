package io.agentguard.core.engine;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Default implementation of {@link PermissionMatcher}.
 * Supports:
 * <ul>
 *   <li>Universal wildcard: {@code *} matches any action</li>
 *   <li>Prefix wildcards: {@code database.*} matches {@code database.query}, {@code database.dev.read}</li>
 *   <li>Suffix wildcards: {@code *.read} matches {@code logs.read}, {@code git.read}</li>
 *   <li>Exact matches: {@code git.read} matches {@code git.read}</li>
 * </ul>
 */
public class DefaultPermissionMatcher implements PermissionMatcher {

    private final ConcurrentHashMap<String, Pattern> compiledPatterns = new ConcurrentHashMap<>();

    @Override
    public boolean matches(String pattern, String action) {
        if (pattern == null || action == null) {
            return false;
        }

        pattern = pattern.trim();
        action = action.trim();

        if (pattern.isEmpty() || action.isEmpty()) {
            return false;
        }

        // 1. Universal wildcard match
        if ("*".equals(pattern)) {
            return true;
        }

        // 2. Exact match fast-path
        if (pattern.equals(action)) {
            return true;
        }

        // 3. Hierarchical pattern matching (e.g. "database.*" or "*.read")
        if (pattern.contains("*")) {
            Pattern regex = compiledPatterns.computeIfAbsent(pattern, this::compilePattern);
            return regex.matcher(action).matches();
        }

        return false;
    }

    private Pattern compilePattern(String wildcardPattern) {
        StringBuilder regex = new StringBuilder("^");
        String[] parts = wildcardPattern.split("\\*", -1);

        for (int i = 0; i < parts.length; i++) {
            if (!parts[i].isEmpty()) {
                regex.append(Pattern.quote(parts[i]));
            }
            if (i < parts.length - 1) {
                regex.append(".*");
            }
        }
        regex.append("$");
        return Pattern.compile(regex.toString());
    }
}
