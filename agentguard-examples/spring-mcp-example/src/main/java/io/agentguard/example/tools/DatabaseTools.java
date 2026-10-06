package io.agentguard.example.tools;

import io.agentguard.spring.annotation.AgentAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Example database tools exposed to Model Context Protocol (MCP) clients.
 * Protected with declarative @AgentAuthorize annotations.
 */
@Service
public class DatabaseTools {

    /**
     * Standard read-only query tool.
     * Evaluates permission "database.query".
     * In development/staging: ALLOW for developer/devops agents.
     * In production: DENY for developer agents due to rule 'deny-dev-prod-db'.
     */
    @AgentAuthorize(
        action = "database.query",
        resourceType = "database",
        resourceId = "#databaseName",
        environment = "#environment"
    )
    public List<Map<String, Object>> queryDatabase(String databaseName, String sql, String environment) {
        return List.of(
            Map.of("id", 1, "status", "active", "db", databaseName)
        );
    }

    /**
     * Destructive drop table tool.
     * Evaluates permission "database.drop".
     * In production: DENY across all agents due to rule 'deny-destructive-drop-prod'.
     */
    @AgentAuthorize(
        action = "database.drop",
        resourceType = "database",
        resourceId = "#databaseName",
        environment = "#environment"
    )
    public String dropTable(String databaseName, String tableName, String environment) {
        return "Dropped table: " + tableName + " from " + databaseName;
    }
}
