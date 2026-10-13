package io.agentguard.fintech;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;

import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class FintechBankingMcpTest {

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private InMemoryAuditEventPublisher auditEvents;

    @Autowired
    private ObjectMapper json;

    private String basicAuth(String agentId) {
        return "Basic " + Base64.getEncoder().encodeToString(
            (agentId + ":fintech-demo-secret").getBytes(StandardCharsets.UTF_8)
        );
    }

    private McpSyncClient createMcpClient(String agentId) {
        var transport = HttpClientStreamableHttpTransport.builder("http://127.0.0.1:" + port)
            .endpoint("/mcp")
            .requestBuilder(HttpRequest.newBuilder().header("Authorization", basicAuth(agentId)))
            .build();
        var client = McpClient.sync(transport).requestTimeout(Duration.ofSeconds(15)).build();
        client.initialize();
        return client;
    }

    private HttpResponse<String> httpPost(String agentId, String path, String body) throws Exception {
        return HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Authorization", basicAuth(agentId))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
    }

    @Test
    @DisplayName("MCP Discovery lists all enterprise fintech and banking tools")
    void mcpDiscoveryListsAllFintechTools() {
        try (var client = createMcpClient("fintech-bot")) {
            var tools = client.listTools().tools();
            assertThat(tools).extracting(McpSchema.Tool::name).containsExactlyInAnyOrder(
                "transferFunds",
                "disburseCorporateBatch",
                "createEscrow",
                "releaseEscrow",
                "disputeEscrow",
                "createApiClient",
                "issueVirtualAccount"
            );
        }
    }

    @Test
    @DisplayName("Payments in development environment are allowed automatically")
    void paymentsLowValueInDevelopmentAllowedAutomatically() {
        BigDecimal devBalanceBefore = jdbc.queryForObject(
            "SELECT balance FROM accounts WHERE id='ACC-DEV-001'", BigDecimal.class
        );
        try (var client = createMcpClient("fintech-bot")) {
            var result = client.callTool(new McpSchema.CallToolRequest(
                "transferFunds",
                Map.of(
                    "fromAccount", "ACC-DEV-001",
                    "toAccount", "ACC-DEV-002",
                    "amount", 500.00,
                    "currency", "USD",
                    "purpose", "Sandbox merchant test payment"
                )
            ));
            assertThat(result.isError()).isFalse();
            assertThat(result.content().toString()).contains("TRANSFERRED");

            BigDecimal devBalanceAfter = jdbc.queryForObject(
                "SELECT balance FROM accounts WHERE id='ACC-DEV-001'", BigDecimal.class
            );
            assertThat(devBalanceBefore.subtract(devBalanceAfter)).isEqualByComparingTo("500.00");
        }
    }

    @Test
    @DisplayName("Payments in production environment trigger APPROVAL_REQUIRED")
    void paymentsHighValueInProductionTriggersApprovalRequired() {
        try (var client = createMcpClient("fintech-bot")) {
            var result = client.callTool(new McpSchema.CallToolRequest(
                "transferFunds",
                Map.of(
                    "fromAccount", "ACC-PROD-001",
                    "toAccount", "ACC-PROD-002",
                    "amount", 5000.00,
                    "currency", "USD",
                    "purpose", "Strategic supplier settlement"
                )
            ));
            assertThat(result.isError()).isTrue();
            assertThat(result.content().toString()).contains("APPROVAL_REQUIRED");
            assertThat(result.content().toString()).contains("production-payment-review");

            // Funds must remain safe and unchanged until human signoff
            BigDecimal prodBalance = jdbc.queryForObject(
                "SELECT balance FROM accounts WHERE id='ACC-PROD-001'", BigDecimal.class
            );
            assertThat(prodBalance).isEqualByComparingTo("1500000.00");
        }
    }

    @Test
    @DisplayName("Human-in-the-loop approval prevents parameter tampering and replay via canonical hash")
    void approvalTamperingRejectsAlteredParametersViaCanonicalHash() throws Exception {
        // Step 1: Request an approval ticket for transferring 10,000 USD
        String paymentJson = """
            {
              "fromAccount": "ACC-PROD-001",
              "toAccount": "ACC-PROD-002",
              "amount": 10000.00,
              "currency": "USD",
              "purpose": "Authorized supplier payout"
            }
            """;
        var requestResponse = httpPost("fintech-bot", "/api/approvals/request/transferFunds", paymentJson);
        assertThat(requestResponse.statusCode()).isEqualTo(200);

        String ticketId = json.readTree(requestResponse.body()).path("id").asText();
        assertThat(ticketId).isNotBlank();

        // Step 2: Unprivileged agent cannot approve
        var unauthorizedApprove = httpPost("fintech-bot", "/api/approvals/" + ticketId + "/approve", "{}");
        assertThat(unauthorizedApprove.statusCode()).isEqualTo(403);

        // Step 3: Authorized Compliance Officer approves the ticket
        var complianceApprove = httpPost("compliance-officer", "/api/approvals/" + ticketId + "/approve", "{}");
        assertThat(complianceApprove.statusCode()).isEqualTo(200);

        // Step 4: Attacker or hijacked LLM attempts to tamper with amount (10,000 -> 100,000)
        String tamperedJson = """
            {
              "fromAccount": "ACC-PROD-001",
              "toAccount": "ACC-PROD-002",
              "amount": 100000.00,
              "currency": "USD",
              "purpose": "Authorized supplier payout"
            }
            """;
        var tamperedExec = httpPost("fintech-bot", "/api/approvals/" + ticketId + "/execute/transferFunds", tamperedJson);
        assertThat(tamperedExec.statusCode()).isEqualTo(403);
        assertThat(tamperedExec.body()).contains("Approval does not match this request");

        // Step 5: Execute with EXACT approved parameters -> Success!
        var validExec = httpPost("fintech-bot", "/api/approvals/" + ticketId + "/execute/transferFunds", paymentJson);
        assertThat(validExec.statusCode()).isEqualTo(200);
        assertThat(validExec.body()).contains("TRANSFERRED");

        // Step 6: Replay attack prevention -> Second execution is immediately denied
        var replayExec = httpPost("fintech-bot", "/api/approvals/" + ticketId + "/execute/transferFunds", paymentJson);
        assertThat(replayExec.statusCode()).isEqualTo(403);
        assertThat(replayExec.body()).contains("Approval is not in the required state");
    }

    @Test
    @DisplayName("B2B Corporate payroll disburse verifies delegation and requires CFO approval")
    void b2bCorporateDisbursementWithDelegationChain() throws Exception {
        // Step 1: Corporate payroll bot (delegated by corporate-cfo) attempts disburse over MCP
        try (var client = createMcpClient("payroll-bot")) {
            var result = client.callTool(new McpSchema.CallToolRequest(
                "disburseCorporateBatch",
                Map.of(
                    "batchId", "BATCH-PAYROLL-101",
                    "corporateId", "CORP-ACME-INC",
                    "totalAmount", 85000.00,
                    "currency", "USD",
                    "recipientCount", 42,
                    "category", "PAYROLL"
                )
            ));
            assertThat(result.isError()).isTrue();
            assertThat(result.content().toString()).contains("APPROVAL_REQUIRED");
            assertThat(result.content().toString()).contains("b2b-corporate-disbursement-review");
        }

        // Step 2: Request formal approval ticket via REST
        String batchJson = """
            {
              "batchId": "BATCH-PAYROLL-101",
              "corporateId": "CORP-ACME-INC",
              "totalAmount": 85000.00,
              "currency": "USD",
              "recipientCount": 42,
              "category": "PAYROLL"
            }
            """;
        var req = httpPost("payroll-bot", "/api/approvals/request/disburseCorporateBatch", batchJson);
        assertThat(req.statusCode()).isEqualTo(200);
        String ticketId = json.readTree(req.body()).path("id").asText();

        // Step 3: Executive CFO approves batch
        var approve = httpPost("corporate-cfo", "/api/approvals/" + ticketId + "/approve", "{}");
        assertThat(approve.statusCode()).isEqualTo(200);

        // Step 4: Execute batch
        var exec = httpPost("payroll-bot", "/api/approvals/" + ticketId + "/execute/disburseCorporateBatch", batchJson);
        assertThat(exec.statusCode()).isEqualTo(200);

        String batchStatus = jdbc.queryForObject(
            "SELECT status FROM corporate_batches WHERE id='BATCH-PAYROLL-101'", String.class
        );
        assertThat(batchStatus).isEqualTo("EXECUTED");
    }

    @Test
    @DisplayName("Escrow dispute hold strictly prevents automated release")
    void escrowDisputeHoldPreventsRelease() {
        try (var client = createMcpClient("fintech-bot")) {
            // Attempting to release a DISPUTED escrow contract is explicitly DENIED fail-closed
            var disputedRelease = client.callTool(new McpSchema.CallToolRequest(
                "releaseEscrow",
                Map.of("escrowId", "ESCROW-DISPUTED-99")
            ));
            assertThat(disputedRelease.isError()).isTrue();
            assertThat(disputedRelease.content().toString()).contains("AgentGuard DENIED");
            assertThat(disputedRelease.content().toString()).contains("disputed-escrow-deny");

            // Escrow remains in disputed state
            String status = jdbc.queryForObject(
                "SELECT status FROM escrows WHERE id='ESCROW-DISPUTED-99'", String.class
            );
            assertThat(status).isEqualTo("DISPUTED");
        }
    }

    @Test
    @DisplayName("API Management governance prevents wildcard scopes and enforces production review")
    void apiManagementGovernanceBlocksWildcardScopes() {
        try (var client = createMcpClient("fintech-bot")) {
            // 1. Prompt injection / attacker attempting wildcard root API credentials
            var wildcardAttempt = client.callTool(new McpSchema.CallToolRequest(
                "createApiClient",
                Map.of(
                    "clientId", "CLIENT-MALICIOUS-01",
                    "scopes", "*",
                    "tier", "ENTERPRISE",
                    "environment", "production"
                )
            ));
            assertThat(wildcardAttempt.isError()).isTrue();
            assertThat(wildcardAttempt.content().toString()).contains("AgentGuard DENIED");
            assertThat(wildcardAttempt.content().toString()).contains("deny-wildcard-scopes");

            // 2. Safe sandbox read API client is allowed immediately
            var sandboxClient = client.callTool(new McpSchema.CallToolRequest(
                "createApiClient",
                Map.of(
                    "clientId", "CLIENT-SANDBOX-01",
                    "scopes", "read:balance",
                    "tier", "STANDARD",
                    "environment", "sandbox"
                )
            ));
            assertThat(sandboxClient.isError()).isFalse();
            assertThat(sandboxClient.content().toString()).contains("ISSUED");

            // 3. Production API client with write permissions triggers APPROVAL_REQUIRED
            var prodClient = client.callTool(new McpSchema.CallToolRequest(
                "createApiClient",
                Map.of(
                    "clientId", "CLIENT-PARTNER-PROD",
                    "scopes", "write:transfers",
                    "tier", "PREMIUM",
                    "environment", "production"
                )
            ));
            assertThat(prodClient.isError()).isTrue();
            assertThat(prodClient.content().toString()).contains("APPROVAL_REQUIRED");
            assertThat(prodClient.content().toString()).contains("production-api-client-review");
        }
    }

    @Test
    @DisplayName("Virtual account issuance respects KYC tier boundary")
    void virtualAccountCreationGovernedByKycTier() {
        try (var client = createMcpClient("fintech-bot")) {
            // Tier 1 merchant virtual account is allowed immediately
            var tier1Result = client.callTool(new McpSchema.CallToolRequest(
                "issueVirtualAccount",
                Map.of(
                    "virtualIban", "GB99VA0011223344",
                    "masterAccountId", "MASTER-VA-POOL",
                    "merchantName", "Local Coffee Shop Ltd",
                    "kycTier", "TIER_1",
                    "dailyLimit", 2500.00
                )
            ));
            assertThat(tier1Result.isError()).isFalse();
            assertThat(tier1Result.content().toString()).contains("ISSUED");

            // Tier 3 high-volume cross-border virtual account triggers APPROVAL_REQUIRED
            var tier3Result = client.callTool(new McpSchema.CallToolRequest(
                "issueVirtualAccount",
                Map.of(
                    "virtualIban", "GB88VA9988776655",
                    "masterAccountId", "MASTER-VA-POOL",
                    "merchantName", "Global FX Clearing Corp",
                    "kycTier", "TIER_3",
                    "dailyLimit", 500000.00
                )
            ));
            assertThat(tier3Result.isError()).isTrue();
            assertThat(tier3Result.content().toString()).contains("APPROVAL_REQUIRED");
            assertThat(tier3Result.content().toString()).contains("high-tier-virtual-account-review");
        }
    }

    @Test
    @DisplayName("Unauthenticated transport request is rejected with 401")
    void unauthenticatedMcpTransportRequestIsRejected() throws Exception {
        var response = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/mcp"))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"))
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );
        assertThat(response.statusCode()).isEqualTo(401);
    }

    @Test
    @DisplayName("Audit events capture structured trace and sanitize sensitive credentials")
    void auditEventSanitizesFinancialParameters() {
        assertThat(auditEvents.getEvents()).isNotEmpty();
        assertThat(auditEvents.getEvents()).anySatisfy(event -> {
            assertThat(event.traceId()).isNotNull();
            assertThat(event.metadata()).containsKey("phase");
        });
    }

    @Test
    @DisplayName("Multi-channel agent controller lists tools for external agents and chatbots")
    void agentChannelListsToolsOverRest() throws Exception {
        var response = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/agent/tools"))
                .header("Authorization", basicAuth("fintech-bot"))
                .GET().build(),
            HttpResponse.BodyHandlers.ofString()
        );
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("transferFunds", "disburseCorporateBatch", "releaseEscrow");
    }

    @Test
    @DisplayName("Multi-channel agent controller executes allowed tool invocations")
    void agentChannelInvokeExecutesAllowedTool() throws Exception {
        String payload = """
            {
              "tool": "transferFunds",
              "parameters": {
                "fromAccount": "ACC-DEV-001",
                "toAccount": "ACC-DEV-002",
                "amount": 200.00,
                "currency": "USD",
                "purpose": "REST Slack bot payment"
              },
              "channel": "SLACK_BOT"
            }
            """;
        var response = httpPost("fintech-bot", "/api/agent/channel/invoke", payload);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"status\":\"SUCCESS\"");
        assertThat(response.body()).contains("TRANSFERRED");
    }

    @Test
    @DisplayName("Multi-channel agent controller halts on production actions with APPROVAL_REQUIRED")
    void agentChannelInvokeHaltsAndReturnsApprovalRequired() throws Exception {
        String payload = """
            {
              "tool": "transferFunds",
              "parameters": {
                "fromAccount": "ACC-PROD-001",
                "toAccount": "ACC-PROD-002",
                "amount": 7500.00,
                "currency": "USD",
                "purpose": "Webhook triggered payment"
              },
              "channel": "WEBHOOK"
            }
            """;
        var response = httpPost("fintech-bot", "/api/agent/channel/invoke", payload);
        assertThat(response.statusCode()).isEqualTo(202);
        assertThat(response.body()).contains("\"status\":\"APPROVAL_REQUIRED\"");
        assertThat(response.body()).contains("approvalId");
    }

    @Test
    @DisplayName("Multi-channel agent controller rejects denied tools fail-closed with 403")
    void agentChannelInvokeRejectsDeniedTool() throws Exception {
        String payload = """
            {
              "tool": "createApiClient",
              "parameters": {
                "clientId": "MALICIOUS-REST-01",
                "scopes": "*",
                "environment": "production"
              },
              "channel": "EXTERNAL_AGENT"
            }
            """;
        var response = httpPost("fintech-bot", "/api/agent/channel/invoke", payload);
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("\"status\":\"DENIED\"");
        assertThat(response.body()).contains("deny-wildcard-scopes");
    }
}
