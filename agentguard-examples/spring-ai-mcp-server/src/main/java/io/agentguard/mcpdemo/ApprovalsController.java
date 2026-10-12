package io.agentguard.mcpdemo;

import io.agentguard.approval.*;
import io.agentguard.core.exception.AgentAccessDeniedException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api/approvals")
public class ApprovalsController {
    private final ApprovalService approvals;
    private final TrustedAgents agents;
    private final OrderTools tools;
    public ApprovalsController(ApprovalService approvals, TrustedAgents agents, OrderTools tools) {
        this.approvals = approvals;
        this.agents = agents; this.tools = tools;
    }
    @PostMapping(path="/request", consumes="application/json")
    public ApprovalTicket request(@RequestBody Map<String, Object> args, Principal principal) {
        return approvals.request(tools.request("refundOrder", args, agents.resolve(principal)), Duration.ofMinutes(5));
    }
    @PostMapping(path="/{id}/approve", consumes="application/json")
    public ApprovalTicket approve(@PathVariable String id, Principal principal) { return approvals.approve(id, agents.resolve(principal)); }
    @PostMapping(path="/{id}/execute", consumes="application/json", produces="application/json")
    public String execute(@PathVariable String id, @RequestBody Map<String, Object> args, Principal principal) {
        return approvals.execute(id, tools.request("refundOrder", args, agents.resolve(principal)),
            verified -> tools.execute("refundOrder", verified.action().parameters()));
    }
    @ExceptionHandler(AgentAccessDeniedException.class)
    ResponseEntity<?> denied(AgentAccessDeniedException exception) { return ResponseEntity.status(403).body(Map.of("error", exception.getMessage())); }
    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<?> invalid(IllegalArgumentException exception) { return ResponseEntity.badRequest().body(Map.of("error", "Invalid approval request")); }
}
