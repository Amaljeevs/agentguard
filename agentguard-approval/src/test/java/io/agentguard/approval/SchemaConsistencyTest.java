package io.agentguard.approval;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Schema Consistency & Drift Prevention Tests")
class SchemaConsistencyTest {

    private static final Set<String> EXPECTED_COLUMNS = Set.of(
        "id", "subject_id", "action", "resource_type", "resource_id",
        "request_hash", "arguments_hash", "policy_revision", "environment",
        "trace_id", "created_at", "expires_at", "state", "decided_by"
    );

    @Test
    @DisplayName("schema-postgresql.sql must be syntactically valid and define all canonical columns")
    void testCanonicalSchemaMatchesExpectedModel() throws Exception {
        InputStream stream = getClass().getResourceAsStream("/schema-postgresql.sql");
        assertThat(stream).isNotNull();
        String sql = new String(stream.readAllBytes(), StandardCharsets.UTF_8);

        JdbcDataSource ds = new JdbcDataSource();
        ds.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");

        try (Connection conn = ds.getConnection();
             Statement stmt = conn.createStatement()) {
            for (String part : sql.split(";")) {
                if (!part.trim().isEmpty()) {
                    stmt.execute(part.trim());
                }
            }

            DatabaseMetaData meta = conn.getMetaData();
            Set<String> actualColumns = new HashSet<>();
            try (ResultSet rs = meta.getColumns(null, null, "agentguard_approvals", null)) {
                while (rs.next()) {
                    actualColumns.add(rs.getString("COLUMN_NAME").toLowerCase());
                }
            }

            assertThat(actualColumns).containsAll(EXPECTED_COLUMNS);
        }
    }
}

