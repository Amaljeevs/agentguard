package io.agentguard.approval;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers(disabledWithoutDocker = true)
@DisplayName("Real PostgreSQL Testcontainers Integration Tests for PostgresApprovalStore")
class PostgresApprovalStoreIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
        .withDatabaseName("agentguard_db")
        .withUsername("testuser")
        .withPassword("testpass");

    private PGSimpleDataSource dataSource;
    private PostgresApprovalStore store;

    @BeforeEach
    void setUp() {
        if (!postgres.isRunning()) {
            return;
        }
        dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgres.getJdbcUrl());
        dataSource.setUser(postgres.getUsername());
        dataSource.setPassword(postgres.getPassword());

        store = new PostgresApprovalStore(dataSource);
        store.initSchema();
    }

    private ApprovalTicket createSampleTicket(String id, ApprovalTicket.State state) {
        Instant now = Instant.now();
        return new ApprovalTicket(
            id,
            "agent-fintech-01",
            "payments.transfer",
            "account",
            "ACC-CORP-999",
            "hash-req-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "hash-arg-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "rev-2026-10",
            "production",
            "trace-tx-100",
            now,
            now.plusSeconds(300),
            state,
            null
        );
    }

    @Test
    @DisplayName("1. Schema creation and idempotent initialization")
    void testSchemaCreationAndMigration() {
        // Calling initSchema repeatedly must succeed without error
        store.initSchema();
        store.initSchema();
    }

    @Test
    @DisplayName("2. Create approval ticket and verify all fields in PostgreSQL")
    void testCreateAndFindTicket() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVAL_REQUIRED);
        store.create(ticket);

        Optional<ApprovalTicket> found = store.find(id);
        assertThat(found).isPresent();
        ApprovalTicket actual = found.get();
        assertThat(actual.id()).isEqualTo(id);
        assertThat(actual.subjectId()).isEqualTo("agent-fintech-01");
        assertThat(actual.action()).isEqualTo("payments.transfer");
        assertThat(actual.resourceType()).isEqualTo("account");
        assertThat(actual.resourceId()).isEqualTo("ACC-CORP-999");
        assertThat(actual.requestHash()).isEqualTo(ticket.requestHash());
        assertThat(actual.argumentsHash()).isEqualTo(ticket.argumentsHash());
        assertThat(actual.policyRevision()).isEqualTo("rev-2026-10");
        assertThat(actual.environment()).isEqualTo("production");
        assertThat(actual.traceId()).isEqualTo("trace-tx-100");
        assertThat(actual.state()).isEqualTo(ApprovalTicket.State.APPROVAL_REQUIRED);
        assertThat(actual.decidedBy()).isNull();
    }

    @Test
    @DisplayName("3. Approve ticket transition")
    void testApproveTicket() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVAL_REQUIRED);
        store.create(ticket);

        ApprovalTicket approved = store.update(id, current -> {
            assertThat(current.state()).isEqualTo(ApprovalTicket.State.APPROVAL_REQUIRED);
            return current.withState(ApprovalTicket.State.APPROVED, "compliance-officer");
        });

        assertThat(approved.state()).isEqualTo(ApprovalTicket.State.APPROVED);
        assertThat(approved.decidedBy()).isEqualTo("compliance-officer");

        ApprovalTicket refetched = store.find(id).orElseThrow();
        assertThat(refetched.state()).isEqualTo(ApprovalTicket.State.APPROVED);
        assertThat(refetched.decidedBy()).isEqualTo("compliance-officer");
    }

    @Test
    @DisplayName("4. Deny ticket transition")
    void testDenyTicket() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVAL_REQUIRED);
        store.create(ticket);

        ApprovalTicket denied = store.update(id, current -> {
            return current.withState(ApprovalTicket.State.DENIED, "risk-officer");
        });

        assertThat(denied.state()).isEqualTo(ApprovalTicket.State.DENIED);
        assertThat(denied.decidedBy()).isEqualTo("risk-officer");
    }

    @Test
    @DisplayName("5. Expire ticket transition")
    void testExpireTicket() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVAL_REQUIRED);
        store.create(ticket);

        ApprovalTicket expired = store.update(id, current -> {
            return current.withState(ApprovalTicket.State.EXPIRED, null);
        });

        assertThat(expired.state()).isEqualTo(ApprovalTicket.State.EXPIRED);
    }

    @Test
    @DisplayName("6. Consume ticket and replay prevention")
    void testConsumeAndReplayPrevention() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVED);
        store.create(ticket);

        // First consumption succeeds
        ApprovalTicket consumed = store.update(id, current -> {
            if (current.state() != ApprovalTicket.State.APPROVED) {
                throw new IllegalStateException("Ticket not in APPROVED state: " + current.state());
            }
            return current.withState(ApprovalTicket.State.CONSUMED, current.decidedBy());
        });
        assertThat(consumed.state()).isEqualTo(ApprovalTicket.State.CONSUMED);

        // Replay attempt fails closed
        assertThatThrownBy(() -> store.update(id, current -> {
            if (current.state() != ApprovalTicket.State.APPROVED) {
                throw new IllegalStateException("Replay attack detected: Ticket already " + current.state());
            }
            return current.withState(ApprovalTicket.State.CONSUMED, current.decidedBy());
        })).isInstanceOf(IllegalStateException.class)
           .hasMessageContaining("Replay attack detected");
    }

    @Test
    @DisplayName("7. SELECT ... FOR UPDATE concurrent consumption: exactly 1 succeeds among multiple consumers")
    void testConcurrentConsumptionWithSelectForUpdate() throws Exception {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVED);
        store.create(ticket);

        int concurrency = 10;
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        CountDownLatch startSignal = new CountDownLatch(1);
        CountDownLatch doneSignal = new CountDownLatch(concurrency);

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        for (int i = 0; i < concurrency; i++) {
            executor.submit(() -> {
                try {
                    startSignal.await();
                    store.update(id, current -> {
                        if (current.state() != ApprovalTicket.State.APPROVED) {
                            throw new IllegalStateException("Already consumed: " + current.state());
                        }
                        return current.withState(ApprovalTicket.State.CONSUMED, "executor");
                    });
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                } finally {
                    doneSignal.countDown();
                }
            });
        }

        startSignal.countDown();
        boolean finished = doneSignal.await(15, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(finished).isTrue();
        assertThat(successCount.get()).isEqualTo(1);
        assertThat(failureCount.get()).isEqualTo(concurrency - 1);

        ApprovalTicket finalTicket = store.find(id).orElseThrow();
        assertThat(finalTicket.state()).isEqualTo(ApprovalTicket.State.CONSUMED);
    }

    @Test
    @DisplayName("8. Transaction rollback preserves state when exception thrown during transition")
    void testTransactionRollback() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVED);
        store.create(ticket);

        assertThatThrownBy(() -> store.update(id, current -> {
            throw new RuntimeException("Simulated business failure during transaction");
        })).isInstanceOf(RuntimeException.class)
           .hasMessageContaining("Simulated business failure");

        // Ticket must remain in original APPROVED state (rolled back)
        ApprovalTicket current = store.find(id).orElseThrow();
        assertThat(current.state()).isEqualTo(ApprovalTicket.State.APPROVED);
    }

    @Test
    @DisplayName("9. Multiple service instances sharing the same PostgreSQL database")
    void testMultipleServiceInstances() {
        PostgresApprovalStore serviceA = new PostgresApprovalStore(dataSource);
        PostgresApprovalStore serviceB = new PostgresApprovalStore(dataSource);

        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVAL_REQUIRED);

        // Instance A creates
        serviceA.create(ticket);

        // Instance B approves
        serviceB.update(id, current -> current.withState(ApprovalTicket.State.APPROVED, "cfo-approver"));

        // Instance A consumes
        ApprovalTicket consumed = serviceA.update(id, current -> {
            assertThat(current.state()).isEqualTo(ApprovalTicket.State.APPROVED);
            return current.withState(ApprovalTicket.State.CONSUMED, current.decidedBy());
        });

        assertThat(consumed.state()).isEqualTo(ApprovalTicket.State.CONSUMED);
        assertThat(consumed.decidedBy()).isEqualTo("cfo-approver");

        // Instance B sees CONSUMED
        assertThat(serviceB.find(id).orElseThrow().state()).isEqualTo(ApprovalTicket.State.CONSUMED);
    }
}

