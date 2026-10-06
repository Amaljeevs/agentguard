package io.agentguard.mcp.error;

/**
 * Standard Model Context Protocol (MCP) and JSON-RPC 2.0 error codes for authorization and governance.
 */
public final class McpErrorCode {

    private McpErrorCode() {}

    /**
     * Agent request lacks valid authentication or identity token is expired.
     */
    public static final int AUTHENTICATION_FAILED = -32001;

    /**
     * Agent identity is authenticated but lacks required permission (DENY).
     */
    public static final int ACCESS_DENIED = -32003;

    /**
     * Requested tool invocation requires external human approval before proceeding.
     */
    public static final int APPROVAL_REQUIRED = -32004;
}
