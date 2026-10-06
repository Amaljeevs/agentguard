package io.agentguard.mcp.error;

import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.core.exception.AgentAuthenticationException;
import io.agentguard.core.model.AuthorizationDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("McpAuthorizationExceptionMapper JSON-RPC Error Mapping Tests")
class McpAuthorizationExceptionMapperTest {

    @Test
    @DisplayName("Should map AgentAccessDeniedException to MCP error -32003 with decision data")
    void shouldMapAccessDeniedTo32003() {
        AuthorizationDecision decision = AuthorizationDecision.deny(
            "Developers cannot query production database",
            "enterprise-policy",
            "deny-dev-prod-db"
        );
        AgentAccessDeniedException ex = new AgentAccessDeniedException("Access denied by policy", decision);

        McpErrorResponse response = McpAuthorizationExceptionMapper.toMcpError(ex);

        assertThat(response.code()).isEqualTo(McpErrorCode.ACCESS_DENIED);
        assertThat(response.code()).isEqualTo(-32003);
        assertThat(response.message()).contains("Access denied by policy");
        assertThat(response.data()).containsEntry("decision", "DENY");
        assertThat(response.data()).containsEntry("ruleId", "deny-dev-prod-db");
        assertThat(response.data()).containsEntry("policy", "enterprise-policy");
    }

    @Test
    @DisplayName("Should map AgentApprovalRequiredException to MCP error -32004 with pending status")
    void shouldMapApprovalRequiredTo32004() {
        AuthorizationDecision decision = AuthorizationDecision.requireApproval(
            "Production deployment requires sign-off",
            "enterprise-policy",
            "prod-deploy-approval"
        );
        AgentApprovalRequiredException ex = new AgentApprovalRequiredException("Approval needed", decision);

        McpErrorResponse response = McpAuthorizationExceptionMapper.toMcpError(ex);

        assertThat(response.code()).isEqualTo(McpErrorCode.APPROVAL_REQUIRED);
        assertThat(response.code()).isEqualTo(-32004);
        assertThat(response.message()).contains("Approval needed");
        assertThat(response.data()).containsEntry("status", "PENDING_APPROVAL");
        assertThat(response.data()).containsEntry("ruleId", "prod-deploy-approval");
    }

    @Test
    @DisplayName("Should map AgentAuthenticationException to MCP error -32001")
    void shouldMapAuthenticationFailedTo32001() {
        AgentAuthenticationException ex = new AgentAuthenticationException("Token has expired");

        McpErrorResponse response = McpAuthorizationExceptionMapper.toMcpError(ex);

        assertThat(response.code()).isEqualTo(McpErrorCode.AUTHENTICATION_FAILED);
        assertThat(response.code()).isEqualTo(-32001);
        assertThat(response.message()).isEqualTo("Token has expired");
    }
}
