package io.agentguard.core.exception;

/**
 * Base unchecked exception for all AgentGuard governance errors.
 */
public class AgentGuardException extends RuntimeException {

    public AgentGuardException(String message) {
        super(message);
    }

    public AgentGuardException(String message, Throwable cause) {
        super(message, cause);
    }
}
