package io.agentguard.fintech.controller;

import io.agentguard.approval.ApprovalService;
import io.agentguard.approval.ApprovalStore;
import io.agentguard.approval.ApprovalTicket;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.fintech.service.FintechBankingTools;
import io.agentguard.fintech.service.TrustedAgentIdentityRegistry;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.Duration;
import java.util.Map;

/**
 * Enterprise approval API for human-in-the-loop and multi-party governance.
 * All tickets are cryptographically bound to the canonical SHA-256 hash of their exact arguments.
 */
@RestController
@RequestMapping("/api/approvals")
public class FintechApprovalsController {

    private final ApprovalService approvalService;
    private final ApprovalStore approvalStore;
    private final TrustedAgentIdentityRegistry identityRegistry;
    private final FintechBankingTools tools;

    public FintechApprovalsController(ApprovalService approvalService,
                                      ApprovalStore approvalStore,
                                      TrustedAgentIdentityRegistry identityRegistry,
                                      FintechBankingTools tools) {
        this.approvalService = approvalService;
        this.approvalStore = approvalStore;
        this.identityRegistry = identityRegistry;
        this.tools = tools;
    }

    @PostMapping(path = "/request/{tool}", consumes = "application/json")
    public ApprovalTicket requestApproval(@PathVariable String tool,
                                          @RequestBody Map<String, Object> args,
                                          Principal principal) {
        var identity = identityRegistry.resolve(principal);
        var request = tools.request(tool, args, identity);
        return approvalService.request(request, Duration.ofMinutes(15));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getTicket(@PathVariable String id) {
        return approvalStore.find(id)
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping(path = "/{id}/approve", consumes = "application/json")
    public ApprovalTicket approveTicket(@PathVariable String id, Principal principal) {
        return approvalService.approve(id, identityRegistry.resolve(principal));
    }

    @PostMapping(path = "/{id}/reject", consumes = "application/json")
    public ApprovalTicket rejectTicket(@PathVariable String id, Principal principal) {
        return approvalService.reject(id, identityRegistry.resolve(principal));
    }

    @PostMapping(path = "/{id}/execute/{tool}", consumes = "application/json", produces = "application/json")
    public String executeTicket(@PathVariable String id,
                                @PathVariable String tool,
                                @RequestBody Map<String, Object> args,
                                Principal principal) {
        var identity = identityRegistry.resolve(principal);
        var request = tools.request(tool, args, identity);
        return approvalService.execute(id, request, verified -> tools.execute(tool, verified.action().parameters()));
    }

    @ExceptionHandler(AgentAccessDeniedException.class)
    public ResponseEntity<?> handleAccessDenied(AgentAccessDeniedException exception) {
        return ResponseEntity.status(403).body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleBadRequest(IllegalArgumentException exception) {
        return ResponseEntity.badRequest().body(Map.of("error", exception.getMessage()));
    }
}
