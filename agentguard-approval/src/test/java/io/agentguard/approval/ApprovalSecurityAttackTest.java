package io.agentguard.approval;

import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.core.engine.DefaultPolicyEngine;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Explicit security tests for approval attack vectors:
 * - Tampering / Modification of approved requests
 * - Replay attacks (multiple execution attempts)
 * - Expired approvals
 * - High concurrency approval consumption
 */
class ApprovalSecurityAttackTest {

    private final Instant now = Instant.parse("2026-10-12T10:00:00Z");
    private final AtomicReference<Instant> currentClockTime = new AtomicReference<>(now);

    private final Clock clock = new Clock() {
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return currentClockTime.get(); }
    };

    private final InMemoryApprovalStore store = new InMemoryApprovalStore();
    private final InMemoryAuditEventPublisher audit = new InMemoryAuditEventPublisher();

    private final PolicySet policy = PolicySet.builder("prod-governance", "1.0")
        .rules(List.of(
            PolicyRule.builder("prod-deploy-approval", RuleEffect.APPROVAL_REQUIRED)
                .targetActions(Set.of("kubernetes.deploy"))
                .build()
        ))
        .build();

    private final DefaultPolicyEngine engine = new DefaultPolicyEngine(policy);
    private final ApprovalService service = new ApprovalService(engine, store, clock, audit, new DefaultParameterSanitizer());

    private AgentIdentity identity(String id, String perm) {
        return AgentIdentity.builder()
            .agentId(id)
            .permission(perm)
            .issuedAt(now.minusSeconds(60))
            .expiresAt(now.plusSeconds(3600))
            .build();
    }

    private AuthorizationRequest deployRequest(String agent, String image) {
        return AuthorizationRequest.of(
            identity(agent, "kubernetes.*"),
            Action.of("kubernetes.deploy", Map.of("image", image, "replicas", 3)),
            Resource.of("k8s_cluster", "prod-cluster"),
            AuthorizationContext.of("production")
        );
    }

    private String createAndApproveTicket(String agent, String image) {
        var ticket = service.request(deployRequest(agent, image), Duration.ofMinutes(10));
        assertThat(ticket.state()).isEqualTo(ApprovalTicket.State.APPROVAL_REQUIRED);

        var approver = identity("lead-sre", "agentguard.approval.approve");
        var approvedTicket = service.approve(ticket.id(), approver);
        assertThat(approvedTicket.state()).isEqualTo(ApprovalTicket.State.APPROVED);
        return ticket.id();
    }

    @Test
    void testModifiedApprovedRequests_tamperedArgumentsAreRejected() {
        String ticketId = createAndApproveTicket("cd-agent", "app:v1.0.0");

        // Attacker attempts to modify the Docker image to a malicious image
        var tamperedRequest = deployRequest("cd-agent", "malicious-pwned:latest");

        assertThatThrownBy(() -> service.execute(ticketId, tamperedRequest, req -> "deployed"))
            .isInstanceOf(AgentAccessDeniedException.class)
            .hasMessageContaining("Approval does not match this request");

        // Ticket remains unconsumed and approved because the hash check was rejected
        assertThat(store.find(ticketId).orElseThrow().state()).isEqualTo(ApprovalTicket.State.APPROVED);
    }

    @Test
    void testModifiedApprovedRequests_tamperedResourceIsRejected() {
        String ticketId = createAndApproveTicket("cd-agent", "app:v1.0.0");

        // Attacker attempts to deploy to different cluster
        var tamperedResource = AuthorizationRequest.of(
            identity("cd-agent", "kubernetes.*"),
            Action.of("kubernetes.deploy", Map.of("image", "app:v1.0.0", "replicas", 3)),
            Resource.of("k8s_cluster", "classified-cluster"),
            AuthorizationContext.of("production")
        );

        assertThatThrownBy(() -> service.execute(ticketId, tamperedResource, req -> "deployed"))
            .isInstanceOf(AgentAccessDeniedException.class)
            .hasMessageContaining("Approval does not match this request");
    }

    @Test
    void testReplayAttacks_cannotExecuteConsumedTicketTwice() {
        String ticketId = createAndApproveTicket("cd-agent", "app:v1.0.0");
        var originalRequest = deployRequest("cd-agent", "app:v1.0.0");

        // 1st Execution: Succeeds
        String result = service.execute(ticketId, originalRequest, req -> "deployment-success");
        assertThat(result).isEqualTo("deployment-success");
        assertThat(store.find(ticketId).orElseThrow().state()).isEqualTo(ApprovalTicket.State.CONSUMED);

        // 2nd Execution (Replay): Fails closed
        assertThatThrownBy(() -> service.execute(ticketId, originalRequest, req -> "replay"))
            .isInstanceOf(AgentAccessDeniedException.class);
    }

    @Test
    void testExpiredApprovals_ticketFailsPastExpiry() {
        String ticketId = createAndApproveTicket("cd-agent", "app:v1.0.0");
        var originalRequest = deployRequest("cd-agent", "app:v1.0.0");

        // Advance clock past the 10-minute TTL
        currentClockTime.set(now.plus(Duration.ofMinutes(15)));

        assertThatThrownBy(() -> service.execute(ticketId, originalRequest, req -> "late-deploy"))
            .isInstanceOf(AgentAccessDeniedException.class)
            .hasMessageContaining("expired");

        assertThat(store.find(ticketId).orElseThrow().state()).isEqualTo(ApprovalTicket.State.EXPIRED);
    }

    @Test
    void testConcurrentApprovalUse_strictlySingleExecutionAllowed() throws Exception {
        String ticketId = createAndApproveTicket("cd-agent", "app:v1.0.0");
        var request = deployRequest("cd-agent", "app:v1.0.0");

        int concurrency = 16;
        var threadPool = Executors.newFixedThreadPool(concurrency);
        var startGate = new CountDownLatch(1);
        var successCount = new AtomicInteger(0);
        var failureCount = new AtomicInteger(0);

        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < concurrency; i++) {
            futures.add(threadPool.submit(() -> {
                try {
                    startGate.await();
                    service.execute(ticketId, request, req -> {
                        successCount.incrementAndGet();
                        return "ok";
                    });
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                }
            }));
        }

        // Release all threads simultaneously
        startGate.countDown();
        for (var future : futures) {
            future.get();
        }
        threadPool.shutdown();

        // Exactly one thread succeeded
        assertThat(successCount.get()).isEqualTo(1);
        // All other 15 threads failed
        assertThat(failureCount.get()).isEqualTo(concurrency - 1);
        assertThat(store.find(ticketId).orElseThrow().state()).isEqualTo(ApprovalTicket.State.CONSUMED);
    }
}

