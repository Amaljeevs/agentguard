package io.agentguard.approval;

import javax.sql.DataSource;
import java.sql.*;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.UnaryOperator;

/**
 * Production-ready PostgreSQL implementation of {@link ApprovalStore}.
 * Guarantees atomic state transitions, row-level locking via {@code SELECT ... FOR UPDATE},
 * and replay prevention across clustered application instances.
 */
public final class PostgresApprovalStore implements ApprovalStore {

    private final DataSource dataSource;

    public PostgresApprovalStore(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource must not be null");
    }

    @Override
    public void create(ApprovalTicket ticket) {
        Objects.requireNonNull(ticket, "ticket must not be null");
        String sql = """
            INSERT INTO agentguard_approvals (
                id, subject_id, action, resource_type, resource_id,
                request_hash, arguments_hash, policy_revision, environment,
                trace_id, created_at, expires_at, state, decided_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ticket.id());
            ps.setString(2, ticket.subjectId());
            ps.setString(3, ticket.action());
            ps.setString(4, ticket.resourceType());
            ps.setString(5, ticket.resourceId());
            ps.setString(6, ticket.requestHash());
            ps.setString(7, ticket.argumentsHash());
            ps.setString(8, ticket.policyRevision());
            ps.setString(9, ticket.environment());
            ps.setString(10, ticket.traceId());
            ps.setTimestamp(11, Timestamp.from(ticket.createdAt()));
            ps.setTimestamp(12, Timestamp.from(ticket.expiresAt()));
            ps.setString(13, ticket.state().name());
            ps.setString(14, ticket.decidedBy());
            ps.executeUpdate();
        } catch (SQLException e) {
            if ("23505".equals(e.getSQLState()) || e.getMessage().contains("Unique") || e.getMessage().contains("duplicate") || e.getMessage().contains("PRIMARY KEY")) {
                throw new IllegalStateException("Duplicate approval ID: " + ticket.id(), e);
            }
            throw new RuntimeException("Failed to persist approval ticket " + ticket.id(), e);
        }
    }

    @Override
    public Optional<ApprovalTicket> find(String id) {
        Objects.requireNonNull(id, "id must not be null");
        String sql = "SELECT * FROM agentguard_approvals WHERE id = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
                return Optional.empty();
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to find approval ticket " + id, e);
        }
    }

    @Override
    public ApprovalTicket update(String id, UnaryOperator<ApprovalTicket> transition) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(transition, "transition must not be null");

        String selectSql = "SELECT * FROM agentguard_approvals WHERE id = ? FOR UPDATE";
        String updateSql = "UPDATE agentguard_approvals SET state = ?, decided_by = ?, expires_at = ? WHERE id = ?";

        try (Connection conn = dataSource.getConnection()) {
            boolean originalAutoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                ApprovalTicket current;
                try (PreparedStatement psSelect = conn.prepareStatement(selectSql)) {
                    psSelect.setString(1, id);
                    try (ResultSet rs = psSelect.executeQuery()) {
                        if (!rs.next()) {
                            throw new IllegalArgumentException("Unknown approval ID: " + id);
                        }
                        current = mapRow(rs);
                    }
                }

                ApprovalTicket next = Objects.requireNonNull(transition.apply(current), "Transition resulted in null ticket");

                try (PreparedStatement psUpdate = conn.prepareStatement(updateSql)) {
                    psUpdate.setString(1, next.state().name());
                    psUpdate.setString(2, next.decidedBy());
                    psUpdate.setTimestamp(3, Timestamp.from(next.expiresAt()));
                    psUpdate.setString(4, id);
                    int updated = psUpdate.executeUpdate();
                    if (updated != 1) {
                        throw new IllegalStateException("Failed to update ticket row for id: " + id);
                    }
                }

                conn.commit();
                return next;
            } catch (Exception ex) {
                conn.rollback();
                if (ex instanceof RuntimeException re) throw re;
                throw new RuntimeException("Transaction failed during approval update", ex);
            } finally {
                conn.setAutoCommit(originalAutoCommit);
            }
        } catch (SQLException e) {
            throw new RuntimeException("Database error updating approval ticket " + id, e);
        }
    }

    public void initSchema() {
        String ddl = """
            CREATE TABLE IF NOT EXISTS agentguard_approvals (
                id VARCHAR(64) PRIMARY KEY,
                subject_id VARCHAR(255) NOT NULL,
                action VARCHAR(255) NOT NULL,
                resource_type VARCHAR(255) NOT NULL,
                resource_id VARCHAR(255) NOT NULL,
                request_hash VARCHAR(128) NOT NULL,
                arguments_hash VARCHAR(128) NOT NULL,
                policy_revision VARCHAR(128) NOT NULL,
                environment VARCHAR(64) NOT NULL,
                trace_id VARCHAR(128) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                state VARCHAR(32) NOT NULL,
                decided_by VARCHAR(255)
            );
            CREATE INDEX IF NOT EXISTS idx_agentguard_approvals_subject ON agentguard_approvals (subject_id);
            CREATE INDEX IF NOT EXISTS idx_agentguard_approvals_state ON agentguard_approvals (state);
            CREATE INDEX IF NOT EXISTS idx_agentguard_approvals_expires ON agentguard_approvals (expires_at);
            """;
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            for (String part : ddl.split(";")) {
                if (!part.trim().isEmpty()) {
                    stmt.execute(part.trim());
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize AgentGuard approval schema", e);
        }
    }

    private static ApprovalTicket mapRow(ResultSet rs) throws SQLException {
        Timestamp createdAtTs = rs.getTimestamp("created_at");
        Timestamp expiresAtTs = rs.getTimestamp("expires_at");
        return new ApprovalTicket(
            rs.getString("id"),
            rs.getString("subject_id"),
            rs.getString("action"),
            rs.getString("resource_type"),
            rs.getString("resource_id"),
            rs.getString("request_hash"),
            rs.getString("arguments_hash"),
            rs.getString("policy_revision"),
            rs.getString("environment"),
            rs.getString("trace_id"),
            createdAtTs.toInstant(),
            expiresAtTs.toInstant(),
            ApprovalTicket.State.valueOf(rs.getString("state")),
            rs.getString("decided_by")
        );
    }
}
