package io.agentguard.audit.sanitizer;

import java.util.Map;

/**
 * Strategy interface for sanitizing action parameters before logging to audit trails.
 * Enforces field masking for secrets, tokens, passwords, and private credentials.
 */
public interface ParameterSanitizer {

    /**
     * Sanitizes the given parameter map by masking sensitive keys.
     *
     * @param parameters the raw action parameters map
     * @return a new map with sensitive entries masked
     */
    Map<String, Object> sanitize(Map<String, Object> parameters);
}
