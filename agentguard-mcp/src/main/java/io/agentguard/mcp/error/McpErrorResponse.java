package io.agentguard.mcp.error;

import java.util.Map;
import java.util.Objects;

/**
 * Standard JSON-RPC 2.0 error representation for MCP tool call rejection.
 */
public record McpErrorResponse(
    int code,
    String message,
    Map<String, Object> data
) {
    public McpErrorResponse {
        Objects.requireNonNull(message, "message must not be null");
        data = data == null ? Map.of() : Map.copyOf(data);
    }

    public static McpErrorResponse of(int code, String message) {
        return new McpErrorResponse(code, message, Map.of());
    }

    public static McpErrorResponse of(int code, String message, Map<String, Object> data) {
        return new McpErrorResponse(code, message, data);
    }
}
