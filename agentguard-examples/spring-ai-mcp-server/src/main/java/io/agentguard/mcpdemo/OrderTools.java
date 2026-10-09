package io.agentguard.mcpdemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.util.Map;

@Service
public class OrderTools {
    private final JdbcTemplate jdbc;
    private final ObjectMapper json;
    public OrderTools(JdbcTemplate jdbc, ObjectMapper json) { this.jdbc = jdbc; this.json = json; }
    public AuthorizationRequest request(String tool, Map<String, Object> args, AgentIdentity identity) {
        long id = orderId(args);
        var environments = jdbc.queryForList("SELECT environment FROM orders WHERE id = ?", String.class, id);
        if (environments.isEmpty()) throw new AgentAccessDeniedException("Unknown order");
        String action = switch (tool) {
            case "readOrder" -> "orders.read";
            case "refundOrder" -> "orders.refund";
            default -> throw new AgentAccessDeniedException("Unknown tool");
        };
        return AuthorizationRequest.of(identity, Action.of(action, args), Resource.of("order", Long.toString(id)),
            AuthorizationContext.of(environments.getFirst()));
    }
    public String execute(String tool, Map<String, Object> args) {
        long id = orderId(args);
        if (tool.equals("refundOrder")) {
            if (jdbc.update("UPDATE orders SET status='REFUNDED' WHERE id=? AND status='PAID'", id) != 1)
                throw new IllegalStateException("Order already refunded or missing");
        }
        try { return json.writeValueAsString(jdbc.queryForMap("SELECT id,product,status FROM orders WHERE id=?", id)); }
        catch (com.fasterxml.jackson.core.JsonProcessingException failure) { throw new IllegalStateException("Cannot encode order"); }
    }
    private long orderId(Map<String, Object> args) {
        try { return new java.math.BigDecimal(String.valueOf(args.get("orderId"))).longValueExact(); }
        catch (RuntimeException failure) { throw new AgentAccessDeniedException("orderId must be an integer"); }
    }
}
