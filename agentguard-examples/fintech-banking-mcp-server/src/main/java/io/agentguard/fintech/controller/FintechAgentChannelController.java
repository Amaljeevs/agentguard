package io.agentguard.fintech.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.approval.ApprovalService;
import io.agentguard.approval.ApprovalTicket;
import io.agentguard.audit.model.AuditEvent;
import io.agentguard.audit.publisher.AuditEventPublisher;
import io.agentguard.audit.sanitizer.ParameterSanitizer;
import io.agentguard.core.engine.PolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.fintech.service.TrustedAgentIdentityRegistry;
import io.agentguard.fintech.tool.FintechBankingTools;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.Duration;
import java.util.*;

/**
 * Multi-channel agent connectivity controller.
 * Exposes guarded fintech tools to external non-MCP agent frameworks, chat platforms (Slack, Teams),
 * webhooks, and backend orchestration services over REST while enforcing the exact same
 * deterministic AgentGuard policies, parameter hashing, and approval workflows.
 */
@RestController
@RequestMapping("/api/agent")
public class FintechAgentChannelController {

    private final FintechBankingTools tools;
    private final TrustedAgentIdentityRegistry identityRegistry;
    private final PolicyEngine policyEngine;
    private final ApprovalService approvalService;
    private final AuditEventPublisher auditPublisher;
    private final ParameterSanitizer sanitizer;
    private final ObjectMapper json;

    public FintechAgentChannelController(FintechBankingTools tools,
                                         TrustedAgentIdentityRegistry identityRegistry,
                                         PolicyEngine policyEngine,
                                         ApprovalService approvalService,
                                         AuditEventPublisher auditPublisher,
                                         ParameterSanitizer sanitizer,
                                         ObjectMapper json) {
        this.tools = tools;
        this.identityRegistry = identityRegistry;
        this.policyEngine = policyEngine;
        this.approvalService = approvalService;
        this.auditPublisher = auditPublisher;
        this.sanitizer = sanitizer;
        this.json = json;
    }

    /**
     * Tool discovery endpoint for non-MCP agents, LLM tool-calling clients, and chatbot connectors.
     */
    @GetMapping("/tools")
    public List<Map<String, Object>> listTools() {
        return List.of(
            Map.of("name", "transferFunds", "description", "Transfer domestic or cross-border funds between bank accounts",
                "parameters", List.of("fromAccount", "toAccount", "amount", "currency", "purpose")),
            Map.of("name", "disburseCorporateBatch", "description", "Execute B2B multi-recipient corporate payroll or vendor settlement batches",
                "parameters", List.of("batchId", "corporateId", "totalAmount", "currency", "recipientCount", "category")),
            Map.of("name", "createEscrow", "description", "Initiate conditional escrow contract holding buyer funds",
                "parameters", List.of("escrowId", "buyerId", "sellerId", "amount", "currency")),
            Map.of("name", "releaseEscrow", "description", "Release settled escrow funds to seller (strictly blocked if disputed)",
                "parameters", List.of("escrowId", "verificationProof")),
            Map.of("name", "disputeEscrow", "description", "Flag an escrow contract as disputed to freeze all automated releases",
                "parameters", List.of("escrowId", "reason")),
            Map.of("name", "createApiClient", "description", "Provision API access scopes, rate plans, and environment policies",
                "parameters", List.of("clientId", "clientName", "scopes", "tier", "rateLimitRps", "environment")),
            Map.of("name", "issueVirtualAccount", "description", "Issue virtual IBAN and merchant sub-accounts bounded by KYC tiers",
                "parameters", List.of("virtualIban", "masterAccountId", "merchantName", "kycTier", "dailyLimit"))
        );
    }

    /**
     * Generic channel invocation endpoint for multi-channel agents (Chatbots, Webhooks, REST orchestrators).
     */
    @PostMapping(path = "/channel/invoke", consumes = "application/json", produces = "application/json")
    public ResponseEntity<Map<String, Object>> invokeTool(@RequestBody Map<String, Object> body, Principal principal) {
        String tool = requireString(body, "tool");
        @SuppressWarnings("unchecked")
        Map<String, Object> parameters = (Map<String, Object>) body.getOrDefault("parameters", Map.of());
        String channel = String.valueOf(body.getOrDefault("channel", "REST_AGENT"));

        AgentIdentity identity = identityRegistry.resolve(principal);
        AuthorizationRequest request = tools.request(tool, parameters, identity);

        String revision = policyEngine.revision();
        var decision = policyEngine.evaluate(request);
        var snapshot = AuditEvent.from(request, decision, sanitizer);
        String correlationId = decision.traceId();

        auditPublisher.publish(snapshot.lifecycle("AUTHORIZATION", correlationId, revision, Map.of("channel", channel)));

        if (decision.isDenied()) {
            throw new AgentAccessDeniedException("AgentGuard DENIED: " + decision.reason()
                + decision.matchedRuleId().map(id -> " [rule: " + id + "]").orElse(""), decision);
        }

        if (decision.isApprovalRequired()) {
            ApprovalTicket ticket = approvalService.request(request, Duration.ofMinutes(15));
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of(
                "status", "APPROVAL_REQUIRED",
                "tool", tool,
                "approvalId", ticket.id(),
                "risk", decision.riskLevel().name(),
                "reason", decision.reason(),
                "message", "Action halted: Multi-party authorization required before execution"
            ));
        }

        // ALLOW: Execute tool directly
        String rawResult = tools.execute(tool, parameters);
        Object parsedResult;
        try {
            parsedResult = json.readValue(rawResult, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            parsedResult = rawResult;
        }

        auditPublisher.publish(snapshot.lifecycle("EXECUTION_SUCCEEDED", correlationId, revision, Map.of("channel", channel)));

        return ResponseEntity.ok(Map.of(
            "status", "SUCCESS",
            "tool", tool,
            "channel", channel,
            "data", parsedResult,
            "traceId", decision.traceId()
        ));
    }

    @ExceptionHandler(AgentAccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AgentAccessDeniedException exception) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
            "status", "DENIED",
            "error", exception.getMessage()
        ));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequest(IllegalArgumentException exception) {
        return ResponseEntity.badRequest().body(Map.of(
            "status", "BAD_REQUEST",
            "error", exception.getMessage()
        ));
    }

    private String requireString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val == null || String.valueOf(val).isBlank()) {
            throw new IllegalArgumentException("Missing required field: " + key);
        }
        return String.valueOf(val);
    }
}
