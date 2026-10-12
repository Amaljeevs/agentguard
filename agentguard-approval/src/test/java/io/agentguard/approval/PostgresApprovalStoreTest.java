package io.agentguard.approval;

import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;

@DisplayName("PostgresApprovalStore Durable Store Integration Tests")
class PostgresApprovalStoreTest {

    private PostgresApprovalStore store;

    @BeforeEach
    void setUp() {
        JdbcDataSource ds = new JdbcDataSource();
        ds.setURL("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        store = new PostgresApprovalStore(ds);
        store.initSchema();
    }

    private ApprovalTicket createSampleTicket(String id, ApprovalTicket.State state) {
        Instant now = Instant.now();
        return new ApprovalTicket(
            id,
            "agent-01",
            "kubernetes.deploy",
            "cluster",
            "prod-cluster",
            "hash-req-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "hash-arg-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "rev-1",
            "production",
            "trace-1",
            now,
            now.plusSeconds(300),
            state,
            null
        );
    }

    @Test
    @DisplayName("Should create and find approval ticket successfully")
    void shouldCreateAndFindTicket() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVAL_REQUIRED);

        store.create(ticket);

        Optional<ApprovalTicket> found = store.find(id);
        assertThat(found).isPresent();
        assertThat(found.get().id()).isEqualTo(id);
        assertThat(found.get().subjectId()).isEqualTo("agent-01");
        assertThat(found.get().action()).isEqualTo("kubernetes.deploy");
        assertThat(found.get().state()).isEqualTo(ApprovalTicket.State.APPROVAL_REQUIRED);
    }

    @Test
    @DisplayName("Should reject duplicate ticket creation")
    void shouldRejectDuplicateTicket() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVAL_REQUIRED);

        store.create(ticket);

        assertThatThrownBy(() -> store.create(ticket))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Duplicate approval ID");
    }

    @Test
    @DisplayName("Should atomically update ticket state and approver")
    void shouldAtomicallyUpdateTicket() {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVAL_REQUIRED);
        store.create(ticket);

        ApprovalTicket updated = store.update(id, current -> {
            assertThat(current.state()).isEqualTo(ApprovalTicket.State.APPROVAL_REQUIRED);
            return current.withState(ApprovalTicket.State.APPROVED, "security-admin");
        });

        assertThat(updated.state()).isEqualTo(ApprovalTicket.State.APPROVED);
        assertThat(updated.decidedBy()).isEqualTo("security-admin");

        ApprovalTicket refetched = store.find(id).orElseThrow();
        assertThat(refetched.state()).isEqualTo(ApprovalTicket.State.APPROVED);
        assertThat(refetched.decidedBy()).isEqualTo("security-admin");
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when updating unknown ticket")
    void shouldThrowWhenUpdatingUnknownTicket() {
        assertThatThrownBy(() -> store.update("non-existent-id", t -> t.withState(ApprovalTicket.State.APPROVED, "admin")))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unknown approval ID");
    }

    @Test
    @DisplayName("Concurrently consuming the same ticket allows exactly ONE caller and blocks race conditions")
    void concurrentConsumption_allowsExactlyOne() throws Exception {
        String id = UUID.randomUUID().toString();
        ApprovalTicket ticket = createSampleTicket(id, ApprovalTicket.State.APPROVED);
        store.create(ticket);

        int threadCount = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CyclicBarrier barrier = new CyclicBarrier(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);

        CountDownLatch latch = new CountDownLatch(threadCount);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    barrier.await();
                    store.update(id, current -> {
                        if (current.state() != ApprovalTicket.State.APPROVED) {
                            throw new IllegalStateException("Already consumed or not approved");
                        }
                        return current.withState(ApprovalTicket.State.CONSUMED, "caller");
                    });
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                } finally {
                    latch.countDown();
                }
            });
        }

        assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        assertThat(successCount.get()).isEqualTo(1);
        assertThat(failureCount.get()).isEqualTo(threadCount - 1);

        ApprovalTicket finalTicket = store.find(id).orElseThrow();
        assertThat(finalTicket.state()).isEqualTo(ApprovalTicket.State.CONSUMED);
    }
}
