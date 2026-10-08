package io.agentguard.orders;

import io.agentguard.spring.annotation.AgentAuthorize;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class ApprovalService {
    private final JdbcTemplate jdbc;
    private final OrderStore store;
    private final TransactionTemplate transaction;

    public ApprovalService(JdbcTemplate jdbc, OrderStore store, TransactionTemplate transaction) {
        this.jdbc = jdbc;
        this.store = store;
        this.transaction = transaction;
    }

    // Called only by the controller after AgentGuard returned APPROVAL_REQUIRED.
    public String enqueue(long orderId) {
        String id = UUID.randomUUID().toString();
        jdbc.update("INSERT INTO refund_approval (id, order_id, requested_by) VALUES (?, ?, ?)",
            id, orderId, actor());
        return id;
    }

    @AgentAuthorize("approvals.read")
    public List<Map<String, Object>> list() {
        return jdbc.queryForList("SELECT * FROM refund_approval ORDER BY created_at DESC");
    }

    @AgentAuthorize(action = "refunds.approve", resourceType = "approval", resourceId = "#approvalId",
        environment = "production")
    public Map<String, Object> approve(String approvalId) {
        // Authorization runs before this transaction, so its audit survives a business rollback.
        return transaction.execute(status -> {
            var rows = jdbc.queryForList("SELECT * FROM refund_approval WHERE id = ? FOR UPDATE", approvalId);
            if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Approval not found");
            var row = rows.getFirst();
            if (!"PENDING".equals(row.get("STATUS"))) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Approval already processed");
            }
            if (actor().equals(row.get("REQUESTED_BY"))) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Requester cannot approve their own refund");
            }
            long orderId = ((Number) row.get("ORDER_ID")).longValue();
            store.refund(orderId);
            jdbc.update("UPDATE refund_approval SET status = 'APPROVED', approved_by = ? WHERE id = ?",
                actor(), approvalId);
            return Map.<String, Object>of("approvalId", approvalId, "orderId", orderId, "status", "REFUNDED");
        });
    }

    private String actor() { return SecurityContextHolder.getContext().getAuthentication().getName(); }
}
