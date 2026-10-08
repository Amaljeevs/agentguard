package io.agentguard.orders;

import io.agentguard.spring.annotation.AgentAuthorize;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

@Service
public class OrderService {
    private final OrderStore store;
    private final JdbcTemplate jdbc;

    public OrderService(OrderStore store, JdbcTemplate jdbc) {
        this.store = store;
        this.jdbc = jdbc;
    }

    @AgentAuthorize(action = "orders.read", resourceType = "database", resourceId = "#database.id",
        environment = "#database.environment")
    public List<OrderStore.Order> list(DatabaseCatalog database) {
        return store.list(database.id());
    }

    @AgentAuthorize(action = "orders.create", resourceType = "database", resourceId = "#database.id",
        environment = "#database.environment")
    public Map<String, Object> create(DatabaseCatalog database, Map<String, Object> payload) {
        String product = text(payload, "product", 120);
        String email = text(payload, "customerEmail", 200);
        BigDecimal amount;
        try { amount = new BigDecimal(String.valueOf(payload.get("amount"))).setScale(2); }
        catch (RuntimeException exception) { throw badRequest("amount must have at most two decimal places"); }
        if (amount.signum() <= 0 || amount.compareTo(new BigDecimal("9999999999.99")) > 0) {
            throw badRequest("amount must be positive and fit DECIMAL(12,2)");
        }
        var key = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            var statement = connection.prepareStatement(
                "INSERT INTO demo_order (database_id, product, customer_email, amount) VALUES (?, ?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, database.id());
            statement.setString(2, product);
            statement.setString(3, email);
            statement.setBigDecimal(4, amount);
            return statement;
        }, key);
        // Secrets in payload are demonstration inputs only and never enter the business tables.
        return Map.of("id", key.getKey().longValue(), "status", "PAID");
    }

    @AgentAuthorize(action = "orders.refund", resourceType = "order", resourceId = "#orderId",
        environment = "#database.environment")
    public Map<String, Object> refund(DatabaseCatalog database, long orderId) {
        store.refund(orderId);
        return Map.of("orderId", orderId, "status", "REFUNDED");
    }

    @AgentAuthorize(action = "orders.delete", resourceType = "order", resourceId = "#orderId",
        environment = "#database.environment")
    public void delete(DatabaseCatalog database, long orderId) {
        jdbc.update("DELETE FROM demo_order WHERE id = ?", orderId);
    }

    private static String text(Map<String, Object> payload, String field, int maxLength) {
        if (!(payload.get(field) instanceof String value) || value.isBlank() || value.length() > maxLength) {
            throw badRequest(field + " must be a nonempty string of at most " + maxLength + " characters");
        }
        return value;
    }

    private static ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
