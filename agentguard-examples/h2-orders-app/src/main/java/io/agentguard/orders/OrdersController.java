package io.agentguard.orders;

import io.agentguard.core.exception.AgentApprovalRequiredException;
import io.agentguard.mcp.error.McpAuthorizationExceptionMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class OrdersController {
    private final OrderStore store;
    private final OrderService orders;
    private final ApprovalService approvals;
    private final InspectionService inspection;

    public OrdersController(OrderStore store, OrderService orders, ApprovalService approvals, InspectionService inspection) {
        this.store = store;
        this.orders = orders;
        this.approvals = approvals;
        this.inspection = inspection;
    }

    @GetMapping("/session")
    public Map<String, Object> session(Authentication authentication, HttpServletRequest request) {
        var csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return Map.of("username", authentication.getName(), "authorities", authentication.getAuthorities(),
            "csrfHeader", csrf.getHeaderName(), "csrfToken", csrf.getToken());
    }

    @GetMapping("/databases/{database}/orders")
    public List<OrderStore.Order> list(@PathVariable String database) {
        return orders.list(DatabaseCatalog.resolve(database));
    }

    @PostMapping("/databases/{database}/orders")
    public ResponseEntity<?> create(@PathVariable String database, @RequestBody Map<String, Object> payload) {
        rejectNulls(payload);
        return ResponseEntity.status(HttpStatus.CREATED).body(orders.create(DatabaseCatalog.resolve(database), payload));
    }

    @PostMapping("/orders/{id}/refund")
    public ResponseEntity<?> refund(@PathVariable long id) {
        // Environment comes from the stored order, never a caller-supplied environment flag.
        var database = store.databaseFor(id);
        try {
            return ResponseEntity.ok(orders.refund(database, id));
        } catch (AgentApprovalRequiredException exception) {
            var error = McpAuthorizationExceptionMapper.toMcpError(exception);
            return ResponseEntity.accepted().body(Map.of("approvalId", approvals.enqueue(id),
                "status", "PENDING_APPROVAL", "error", error));
        }
    }

    @DeleteMapping("/orders/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable long id) {
        orders.delete(store.databaseFor(id), id);
    }

    @GetMapping("/approvals")
    public Object approvals() { return approvals.list(); }

    @PostMapping("/approvals/{id}/approve")
    public Object approve(@PathVariable String id) { return approvals.approve(id); }

    @GetMapping("/audit")
    public Object audit() { return inspection.audits(); }

    @PostMapping("/policy-preview")
    public Object preview() { return inspection.previews(); }

    private static void rejectNulls(Object value) {
        // 0.1.0's sanitizer uses Map.copyOf/List.copyOf, which reject null values.
        if (value == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Null payload values are unsupported");
        if (value instanceof Map<?, ?> map) map.values().forEach(OrdersController::rejectNulls);
        if (value instanceof List<?> list) list.forEach(OrdersController::rejectNulls);
    }
}
