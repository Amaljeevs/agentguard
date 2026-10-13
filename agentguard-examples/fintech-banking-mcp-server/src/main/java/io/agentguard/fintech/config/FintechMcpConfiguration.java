package io.agentguard.fintech.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.approval.ApprovalService;
import io.agentguard.approval.ApprovalStore;
import io.agentguard.approval.InMemoryApprovalStore;
import io.agentguard.audit.publisher.*;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.fintech.tool.FintechBankingTools;
import io.agentguard.fintech.service.TrustedAgentIdentityRegistry;
import io.agentguard.spring.ai.GuardedToolCallback;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.WebMvcStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import org.springframework.ai.mcp.McpToolUtils;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import java.time.Clock;
import java.time.Duration;
import java.util.*;

@Configuration(proxyBeanMethods = false)
public class FintechMcpConfiguration {

    @Bean
    public WebMvcStreamableServerTransportProvider mcpTransport(TrustedAgentIdentityRegistry registry) {
        return WebMvcStreamableServerTransportProvider.builder()
            .mcpEndpoint("/mcp")
            .contextExtractor(request -> McpTransportContext.create(Map.of(
                "agentguard.identity",
                registry.resolve(request.principal().orElse(null))
            )))
            .build();
    }

    @Bean
    public RouterFunction<ServerResponse> mcpRoutes(WebMvcStreamableServerTransportProvider transport) {
        return transport.getRouterFunction();
    }

    @Bean
    public InMemoryAuditEventPublisher inMemoryAuditEvents() {
        return new InMemoryAuditEventPublisher();
    }

    @Bean
    @Primary
    public AuditEventPublisher auditPublisher(InMemoryAuditEventPublisher inMemory, ParameterSanitizer sanitizer) {
        return new CompositeAuditEventPublisher(
            List.of(inMemory, new JsonAuditEventPublisher(sanitizer)),
            AuditFailureMode.FAIL_CLOSED
        );
    }

    @Bean
    public ApprovalStore approvalStore() {
        return new InMemoryApprovalStore();
    }

    @Bean
    public ApprovalService approvalService(PolicyEngine engine,
                                          ApprovalStore store,
                                          AuditEventPublisher audit,
                                          ParameterSanitizer sanitizer) {
        return new ApprovalService(engine, store, Clock.systemUTC(), audit, sanitizer);
    }

    @Bean(destroyMethod = "close")
    public McpSyncServer fintechMcpServer(WebMvcStreamableServerTransportProvider transport,
                                         FintechBankingTools tools,
                                         PolicyEngine engine,
                                         AuditEventPublisher audit,
                                         ParameterSanitizer sanitizer,
                                         ApprovalService approvals,
                                         ObjectMapper json) {
        Map<String, String> schemas = Map.of(
            "transferFunds", """
                {
                  "type": "object",
                  "properties": {
                    "fromAccount": { "type": "string" },
                    "toAccount": { "type": "string" },
                    "amount": { "type": "number" },
                    "currency": { "type": "string" },
                    "purpose": { "type": "string" }
                  },
                  "required": ["fromAccount", "toAccount", "amount"]
                }
                """,
            "disburseCorporateBatch", """
                {
                  "type": "object",
                  "properties": {
                    "batchId": { "type": "string" },
                    "corporateId": { "type": "string" },
                    "totalAmount": { "type": "number" },
                    "currency": { "type": "string" },
                    "recipientCount": { "type": "integer" },
                    "category": { "type": "string" }
                  },
                  "required": ["batchId", "corporateId", "totalAmount"]
                }
                """,
            "createEscrow", """
                {
                  "type": "object",
                  "properties": {
                    "escrowId": { "type": "string" },
                    "buyerId": { "type": "string" },
                    "sellerId": { "type": "string" },
                    "amount": { "type": "number" },
                    "currency": { "type": "string" }
                  },
                  "required": ["escrowId", "buyerId", "sellerId", "amount"]
                }
                """,
            "releaseEscrow", """
                {
                  "type": "object",
                  "properties": {
                    "escrowId": { "type": "string" },
                    "verificationProof": { "type": "string" }
                  },
                  "required": ["escrowId"]
                }
                """,
            "disputeEscrow", """
                {
                  "type": "object",
                  "properties": {
                    "escrowId": { "type": "string" },
                    "reason": { "type": "string" }
                  },
                  "required": ["escrowId", "reason"]
                }
                """,
            "createApiClient", """
                {
                  "type": "object",
                  "properties": {
                    "clientId": { "type": "string" },
                    "clientName": { "type": "string" },
                    "scopes": { "type": "string" },
                    "tier": { "type": "string" },
                    "rateLimitRps": { "type": "integer" },
                    "environment": { "type": "string" }
                  },
                  "required": ["clientId", "scopes"]
                }
                """,
            "issueVirtualAccount", """
                {
                  "type": "object",
                  "properties": {
                    "virtualIban": { "type": "string" },
                    "masterAccountId": { "type": "string" },
                    "merchantName": { "type": "string" },
                    "kycTier": { "type": "string" },
                    "dailyLimit": { "type": "number" }
                  },
                  "required": ["virtualIban", "masterAccountId", "dailyLimit"]
                }
                """
        );

        Map<String, String> descriptions = Map.of(
            "transferFunds", "Transfer domestic or cross-border funds between bank accounts subject to policy threshold limits",
            "disburseCorporateBatch", "Execute B2B multi-recipient corporate payroll or vendor settlement batches",
            "createEscrow", "Initiate a conditional escrow contract holding buyer funds for milestone release",
            "releaseEscrow", "Release settled escrow funds to seller upon verified milestone completion (blocked if disputed)",
            "disputeEscrow", "Flag an escrow contract as disputed to freeze all automated releases",
            "createApiClient", "Provision API access scopes, rate plans, and environment policies for fintech partners",
            "issueVirtualAccount", "Issue virtual IBAN and merchant sub-accounts bounded by regulatory KYC tiers"
        );

        List<ToolCallback> guardedCallbacks = new ArrayList<>();
        for (Map.Entry<String, String> entry : schemas.entrySet()) {
            String toolName = entry.getKey();
            String schema = entry.getValue();
            String description = descriptions.get(toolName);

            ToolCallback rawTool = new ToolCallback() {
                @Override
                public ToolDefinition getToolDefinition() {
                    return ToolDefinition.builder()
                        .name(toolName)
                        .description(description)
                        .inputSchema(schema)
                        .build();
                }

                @Override
                public String call(String input) {
                    try {
                        Map<String, Object> args = json.readValue(input, new TypeReference<>() {});
                        return tools.execute(toolName, args);
                    } catch (JsonProcessingException e) {
                        throw new IllegalArgumentException("Invalid tool arguments: " + e.getMessage(), e);
                    }
                }
            };

            guardedCallbacks.add(new GuardedToolCallback(
                rawTool,
                (tool, arguments, context) -> {
                    var exchange = McpToolUtils.getMcpExchange(context)
                        .orElseThrow(() -> new IllegalStateException("Missing MCP exchange context"));
                    var identity = (AgentIdentity) exchange.transportContext().get("agentguard.identity");
                    return tools.request(tool, arguments, identity);
                },
                engine,
                audit,
                sanitizer,
                approvals,
                Duration.ofMinutes(15)
            ));
        }

        return McpServer.sync(transport)
            .serverInfo("agentguard-fintech-banking", "0.2.1")
            .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
            .tools(McpToolUtils.toSyncToolSpecifications(guardedCallbacks.toArray(ToolCallback[]::new)))
            .build();
    }
}

