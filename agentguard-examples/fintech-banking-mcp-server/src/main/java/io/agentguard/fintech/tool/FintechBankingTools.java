package io.agentguard.fintech.tool;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.Action;
import io.agentguard.core.model.AgentIdentity;
import io.agentguard.core.model.AuthorizationContext;
import io.agentguard.core.model.AuthorizationRequest;
import io.agentguard.core.model.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.*;

/**
 * Enterprise tool implementations and request mapping connectors.
 * All tools map deterministic AgentGuard AuthorizationRequest instances before execution.
 */
@Service
public class FintechBankingTools {

    private final JdbcTemplate jdbc;
    private final ObjectMapper json;

    public FintechBankingTools(JdbcTemplate jdbc, ObjectMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public AuthorizationRequest request(String tool, Map<String, Object> args, AgentIdentity identity) {
        Objects.requireNonNull(identity, "identity must not be null");
        Objects.requireNonNull(args, "arguments must not be null");

        return switch (tool) {
            case "transferFunds" -> buildTransferRequest(args, identity);
            case "disburseCorporateBatch" -> buildDisbursementRequest(args, identity);
            case "createEscrow" -> buildCreateEscrowRequest(args, identity);
            case "releaseEscrow" -> buildReleaseEscrowRequest(args, identity);
            case "disputeEscrow" -> buildDisputeEscrowRequest(args, identity);
            case "createApiClient" -> buildApiClientRequest(args, identity);
            case "issueVirtualAccount" -> buildVirtualAccountRequest(args, identity);
            default -> throw new AgentAccessDeniedException("Unknown fintech tool: " + tool);
        };
    }

    @Transactional
    public String execute(String tool, Map<String, Object> args) {
        try {
            Map<String, Object> result = switch (tool) {
                case "transferFunds" -> executeTransfer(args);
                case "disburseCorporateBatch" -> executeCorporateDisbursement(args);
                case "createEscrow" -> executeCreateEscrow(args);
                case "releaseEscrow" -> executeReleaseEscrow(args);
                case "disputeEscrow" -> executeDisputeEscrow(args);
                case "createApiClient" -> executeCreateApiClient(args);
                case "issueVirtualAccount" -> executeIssueVirtualAccount(args);
                default -> throw new AgentAccessDeniedException("Unknown tool: " + tool);
            };
            return json.writeValueAsString(result);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize execution result", e);
        }
    }

    // -------------------------------------------------------------------------
    // Request Mapping Builders
    // -------------------------------------------------------------------------

    private AuthorizationRequest buildTransferRequest(Map<String, Object> args, AgentIdentity identity) {
        String fromAccount = requireString(args, "fromAccount");
        var rows = jdbc.queryForList("SELECT environment FROM accounts WHERE id = ?", String.class, fromAccount);
        if (rows.isEmpty()) {
            throw new AgentAccessDeniedException("Source account does not exist: " + fromAccount);
        }
        String environment = rows.getFirst();
        return AuthorizationRequest.of(
            identity,
            Action.of("payments.transfer", args),
            Resource.of("account", fromAccount),
            AuthorizationContext.of(environment)
        );
    }

    private AuthorizationRequest buildDisbursementRequest(Map<String, Object> args, AgentIdentity identity) {
        String batchId = requireString(args, "batchId");
        var rows = jdbc.queryForList("SELECT category FROM corporate_batches WHERE id = ?", String.class, batchId);
        if (rows.isEmpty()) {
            throw new AgentAccessDeniedException("Corporate batch not found: " + batchId);
        }
        String category = rows.getFirst();
        String actionName = "PAYROLL".equalsIgnoreCase(category) ? "b2b.payroll.disburse" : "b2b.vendor.disburse";
        return AuthorizationRequest.of(
            identity,
            Action.of(actionName, args),
            Resource.of("corporate-batch", batchId),
            AuthorizationContext.of("production")
        );
    }

    private AuthorizationRequest buildCreateEscrowRequest(Map<String, Object> args, AgentIdentity identity) {
        String escrowId = requireString(args, "escrowId");
        return AuthorizationRequest.of(
            identity,
            Action.of("escrow.create", args),
            Resource.of("escrow", escrowId),
            AuthorizationContext.of("production")
        );
    }

    private AuthorizationRequest buildReleaseEscrowRequest(Map<String, Object> args, AgentIdentity identity) {
        String escrowId = requireString(args, "escrowId");
        var rows = jdbc.queryForList("SELECT status, environment FROM escrows WHERE id = ?", escrowId);
        if (rows.isEmpty()) {
            throw new AgentAccessDeniedException("Escrow contract not found: " + escrowId);
        }
        Map<String, Object> row = rows.getFirst();
        String status = (String) row.get("STATUS");
        String environment = (String) row.get("ENVIRONMENT");

        String resourceType = "DISPUTED".equalsIgnoreCase(status) ? "escrow-disputed" : "escrow";

        return AuthorizationRequest.of(
            identity,
            Action.of("escrow.release", args),
            Resource.of(resourceType, escrowId),
            AuthorizationContext.of(environment)
        );
    }

    private AuthorizationRequest buildDisputeEscrowRequest(Map<String, Object> args, AgentIdentity identity) {
        String escrowId = requireString(args, "escrowId");
        return AuthorizationRequest.of(
            identity,
            Action.of("escrow.dispute", args),
            Resource.of("escrow", escrowId),
            AuthorizationContext.of("production")
        );
    }

    private AuthorizationRequest buildApiClientRequest(Map<String, Object> args, AgentIdentity identity) {
        String clientId = requireString(args, "clientId");
        String scopes = String.valueOf(args.getOrDefault("scopes", ""));
        String environment = String.valueOf(args.getOrDefault("environment", "sandbox"));

        String actionName = (scopes.contains("*") || scopes.toLowerCase().contains("admin"))
            ? "apimgmt.wildcard"
            : "apimgmt.client.create";

        return AuthorizationRequest.of(
            identity,
            Action.of(actionName, args),
            Resource.of("api-client", clientId),
            AuthorizationContext.of(environment)
        );
    }

    private AuthorizationRequest buildVirtualAccountRequest(Map<String, Object> args, AgentIdentity identity) {
        String virtualIban = requireString(args, "virtualIban");
        String kycTier = String.valueOf(args.getOrDefault("kycTier", "TIER_1"));

        String environment = "TIER_3".equalsIgnoreCase(kycTier) ? "production-tier3" : "production";

        return AuthorizationRequest.of(
            identity,
            Action.of("accounts.virtual.create", args),
            Resource.of("virtual-account", virtualIban),
            AuthorizationContext.of(environment)
        );
    }

    // -------------------------------------------------------------------------
    // Execution Handlers
    // -------------------------------------------------------------------------

    private Map<String, Object> executeTransfer(Map<String, Object> args) {
        String fromAccount = requireString(args, "fromAccount");
        String toAccount = requireString(args, "toAccount");
        BigDecimal amount = requireBigDecimal(args, "amount");
        String currency = String.valueOf(args.getOrDefault("currency", "USD"));

        int deducted = jdbc.update("UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
            amount, fromAccount, amount);
        if (deducted != 1) {
            throw new IllegalStateException("Insufficient funds or source account inactive: " + fromAccount);
        }
        jdbc.update("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, toAccount);

        BigDecimal newBalance = jdbc.queryForObject("SELECT balance FROM accounts WHERE id = ?", BigDecimal.class, fromAccount);
        return Map.of(
            "status", "TRANSFERRED",
            "fromAccount", fromAccount,
            "toAccount", toAccount,
            "amount", amount,
            "currency", currency,
            "remainingBalance", newBalance
        );
    }

    private Map<String, Object> executeCorporateDisbursement(Map<String, Object> args) {
        String batchId = requireString(args, "batchId");
        int updated = jdbc.update("UPDATE corporate_batches SET status = 'EXECUTED' WHERE id = ? AND status = 'PENDING'", batchId);
        if (updated != 1) {
            throw new IllegalStateException("Batch already executed or not found: " + batchId);
        }
        return Map.of("status", "EXECUTED", "batchId", batchId);
    }

    private Map<String, Object> executeCreateEscrow(Map<String, Object> args) {
        String escrowId = requireString(args, "escrowId");
        String buyerId = requireString(args, "buyerId");
        String sellerId = requireString(args, "sellerId");
        BigDecimal amount = requireBigDecimal(args, "amount");
        String currency = String.valueOf(args.getOrDefault("currency", "USD"));

        jdbc.update("INSERT INTO escrows (id, buyer_id, seller_id, amount, currency, environment, status) VALUES (?, ?, ?, ?, ?, 'production', 'ACTIVE')",
            escrowId, buyerId, sellerId, amount, currency);
        return Map.of("status", "ACTIVE", "escrowId", escrowId, "amount", amount, "currency", currency);
    }

    private Map<String, Object> executeReleaseEscrow(Map<String, Object> args) {
        String escrowId = requireString(args, "escrowId");
        int updated = jdbc.update("UPDATE escrows SET status = 'RELEASED' WHERE id = ? AND status = 'ACTIVE'", escrowId);
        if (updated != 1) {
            throw new IllegalStateException("Escrow cannot be released (may be DISPUTED or already RELEASED): " + escrowId);
        }
        return Map.of("status", "RELEASED", "escrowId", escrowId);
    }

    private Map<String, Object> executeDisputeEscrow(Map<String, Object> args) {
        String escrowId = requireString(args, "escrowId");
        int updated = jdbc.update("UPDATE escrows SET status = 'DISPUTED' WHERE id = ?", escrowId);
        if (updated != 1) {
            throw new IllegalStateException("Escrow contract not found: " + escrowId);
        }
        return Map.of("status", "DISPUTED", "escrowId", escrowId);
    }

    private Map<String, Object> executeCreateApiClient(Map<String, Object> args) {
        String clientId = requireString(args, "clientId");
        String clientName = String.valueOf(args.getOrDefault("clientName", "API Client"));
        String scopes = String.valueOf(args.getOrDefault("scopes", "read:balance"));
        String tier = String.valueOf(args.getOrDefault("tier", "STANDARD"));
        int rateLimitRps = Integer.parseInt(String.valueOf(args.getOrDefault("rateLimitRps", "50")));
        String environment = String.valueOf(args.getOrDefault("environment", "sandbox"));

        jdbc.update("INSERT INTO api_clients (client_id, client_name, scopes, tier, rate_limit_rps, environment, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')",
            clientId, clientName, scopes, tier, rateLimitRps, environment);
        return Map.of("status", "ISSUED", "clientId", clientId, "scopes", scopes, "environment", environment);
    }

    private Map<String, Object> executeIssueVirtualAccount(Map<String, Object> args) {
        String virtualIban = requireString(args, "virtualIban");
        String masterAccountId = requireString(args, "masterAccountId");
        String merchantName = String.valueOf(args.getOrDefault("merchantName", "Merchant"));
        String kycTier = String.valueOf(args.getOrDefault("kycTier", "TIER_1"));
        BigDecimal dailyLimit = requireBigDecimal(args, "dailyLimit");

        jdbc.update("INSERT INTO virtual_accounts (virtual_iban, master_account_id, merchant_name, kyc_tier, daily_limit, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')",
            virtualIban, masterAccountId, merchantName, kycTier, dailyLimit);
        return Map.of("status", "ISSUED", "virtualIban", virtualIban, "kycTier", kycTier, "dailyLimit", dailyLimit);
    }

    // -------------------------------------------------------------------------
    // Helper Extractors
    // -------------------------------------------------------------------------

    private String requireString(Map<String, Object> args, String key) {
        Object val = args.get(key);
        if (val == null || String.valueOf(val).isBlank()) {
            throw new AgentAccessDeniedException("Missing required parameter: " + key);
        }
        return String.valueOf(val);
    }

    private BigDecimal requireBigDecimal(Map<String, Object> args, String key) {
        Object val = args.get(key);
        if (val == null) {
            throw new AgentAccessDeniedException("Missing required numeric parameter: " + key);
        }
        try {
            return new BigDecimal(String.valueOf(val));
        } catch (NumberFormatException e) {
            throw new AgentAccessDeniedException("Invalid numeric parameter for " + key + ": " + val);
        }
    }
}

