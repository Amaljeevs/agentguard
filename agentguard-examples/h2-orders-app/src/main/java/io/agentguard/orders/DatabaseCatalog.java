package io.agentguard.orders;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public record DatabaseCatalog(String id, String environment) {
    public static DatabaseCatalog resolve(String id) {
        return switch (id) {
            case "orders-dev" -> new DatabaseCatalog(id, "development");
            case "orders-prod" -> new DatabaseCatalog(id, "production");
            default -> throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown database");
        };
    }
}
