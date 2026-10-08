package io.agentguard.orders;

import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.mcp.error.McpAuthorizationExceptionMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestControllerAdvice
public class ApiErrors {
    @ExceptionHandler(AgentAccessDeniedException.class)
    ResponseEntity<?> denied(AgentAccessDeniedException exception) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(Map.of("error", McpAuthorizationExceptionMapper.toMcpError(exception)));
    }

    @ExceptionHandler(AgentApprovalRequiredException.class)
    ResponseEntity<?> approval(AgentApprovalRequiredException exception) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(Map.of("error", McpAuthorizationExceptionMapper.toMcpError(exception)));
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<?> status(ResponseStatusException exception) {
        return ResponseEntity.status(exception.getStatusCode())
            .body(Map.of("message", exception.getReason() == null ? "Request failed" : exception.getReason()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<?> malformedJson() {
        return ResponseEntity.badRequest().body(Map.of("message", "Expected a valid JSON object"));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    ResponseEntity<?> conflict() {
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(Map.of("message", "Operation conflicts with stored data"));
    }
}
