package io.agentguard.orders;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.List;

@Repository
public class OrderStore {
    private final JdbcTemplate jdbc;

    public OrderStore(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public record Order(long id, String databaseId, String product, String customerEmail,
                        BigDecimal amount, String status) {}

    public List<Order> list(String database) {
        return jdbc.query("SELECT * FROM demo_order WHERE database_id = ? ORDER BY id", (rs, row) ->
            new Order(rs.getLong("id"), rs.getString("database_id"), rs.getString("product"),
                rs.getString("customer_email"), rs.getBigDecimal("amount"), rs.getString("status")), database);
    }

    public DatabaseCatalog databaseFor(long orderId) {
        var ids = jdbc.queryForList("SELECT database_id FROM demo_order WHERE id = ?", String.class, orderId);
        if (ids.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Order not found");
        return DatabaseCatalog.resolve(ids.getFirst());
    }

    public void refund(long orderId) {
        if (jdbc.update("UPDATE demo_order SET status = 'REFUNDED' WHERE id = ? AND status = 'PAID'", orderId) != 1) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Order is missing or already refunded");
        }
    }
}
