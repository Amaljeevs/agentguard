package io.agentguard.mcp.error;

import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.core.exception.AgentAuthenticationException;
import io.agentguard.core.exception.AgentGuardException;

import java.util.HashMap;
import java.util.Map;

/**
 * Maps AgentGuard exceptions into standard Model Context Protocol (MCP) JSON-RPC 2.0 error responses.
 */
public final class McpAuthorizationExceptionMapper {

    private McpAuthorizationExceptionMapper() {}

    public static McpErrorResponse toMcpError(Throwable throwable) {
        if (throwable instanceof AgentAccessDeniedException e) {
            Map<String, Object> data = new HashMap<>();
            if (e.getDecision() != null) {
                data.put("decision", e.getDecision().decision().name());
                e.getDecision().matchedRuleId().ifPresent(rule -> data.put("ruleId", rule));
                e.getDecision().matchedPolicyName().ifPresent(p -> data.put("policy", p));
            }
            return McpErrorResponse.of(McpErrorCode.ACCESS_DENIED, e.getMessage(), data);
        }

        if (throwable instanceof AgentApprovalRequiredException e) {
            Map<String, Object> data = new HashMap<>();
            if (e.getDecision() != null) {
                data.put("decision", e.getDecision().decision().name());
                e.getDecision().matchedRuleId().ifPresent(rule -> data.put("ruleId", rule));
                data.put("status", "PENDING_APPROVAL");
            }
            return McpErrorResponse.of(McpErrorCode.APPROVAL_REQUIRED, e.getMessage(), data);
        }

        if (throwable instanceof AgentAuthenticationException e) {
            return McpErrorResponse.of(McpErrorCode.AUTHENTICATION_FAILED, e.getMessage());
        }

        if (throwable instanceof AgentGuardException e) {
            return McpErrorResponse.of(McpErrorCode.ACCESS_DENIED, e.getMessage());
        }

        return McpErrorResponse.of(-32603, "Internal server error: " + throwable.getMessage());
    }
}
