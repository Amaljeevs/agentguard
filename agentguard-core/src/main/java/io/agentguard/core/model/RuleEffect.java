package io.agentguard.core.model;

/**
 * The evaluation outcome specified by a policy rule when its target matches.
 */
public enum RuleEffect {
    ALLOW,
    DENY,
    APPROVAL_REQUIRED
}
