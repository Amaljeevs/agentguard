package io.agentguard.web.api;

import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentAuthenticationException;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.time.Instant;

/** Stable, minimal API errors that do not expose token, policy or argument internals. */
@RestControllerAdvice(assignableTypes = AuthorizationController.class)
public final class AuthorizationApiExceptionHandler {
    public record ApiError(String code, String message, Instant timestamp) {}

    @ExceptionHandler(AgentAuthenticationException.class)
    ResponseEntity<ApiError> unauthenticated() {
        return response(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED", "Verified agent identity is required");
    }

    @ExceptionHandler(AgentAccessDeniedException.class)
    ResponseEntity<ApiError> forbidden() {
        return response(HttpStatus.FORBIDDEN, "FORBIDDEN", "Agent identity is not authorized for this request");
    }

    @ExceptionHandler({IllegalArgumentException.class, NullPointerException.class})
    ResponseEntity<ApiError> invalid() {
        return response(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Authorization request is invalid");
    }

    private static ResponseEntity<ApiError> response(HttpStatus status, String code, String message) {
        return ResponseEntity.status(status).body(new ApiError(code, message, Instant.now()));
    }
}
