package io.agentguard.core.model;

/**
 * Deterministic authorization decision outcomes.
 */
public enum Decision {
    /**
     * The requested action is explicitly permitted by active policy.
     */
    ALLOW,

    /**
     * The requested action is prohibited (either by default or an explicit deny rule).
     */
    DENY,

    /**
     * The action is potentially permitted but exceeds autonomous risk thresholds,
     * requiring explicit human or quorum sign-off before proceeding.
     */
    APPROVAL_REQUIRED
}
