package io.agentguard.core.exception;

/**
 * Thrown when an agent request cannot be verified, is missing identity provenance,
 * or has expired temporal validity.
 */
public class AgentAuthenticationException extends AgentGuardException {

    public AgentAuthenticationException(String message) {
        super(message);
    }

    public AgentAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
