package io.agentguard.core.exception;

/**
 * Thrown during bootstrap if a policy definition is structurally corrupt,
 * violates schema constraints, or has contradictory syntax.
 */
public class InvalidPolicyException extends AgentGuardException {

    public InvalidPolicyException(String message) {
        super(message);
    }

    public InvalidPolicyException(String message, Throwable cause) {
        super(message, cause);
    }
}
