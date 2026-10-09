package io.agentguard.approval;

import io.agentguard.audit.publisher.InMemoryAuditEventPublisher;
import io.agentguard.audit.sanitizer.DefaultParameterSanitizer;
import io.agentguard.core.engine.*;
import io.agentguard.core.exception.AgentAccessDeniedException;
import io.agentguard.core.model.*;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.assertj.core.api.Assertions.*;

class ApprovalServiceTest {
    private final Instant now = Instant.parse("2026-01-01T00:00:00Z");
    private final AtomicReference<Instant> currentTime = new AtomicReference<>(now);
    private final Clock clock = new Clock() {
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return currentTime.get(); }
    };
    private final InMemoryApprovalStore store = new InMemoryApprovalStore();
    private final InMemoryAuditEventPublisher audit = new InMemoryAuditEventPublisher();
    private final AtomicReference<DefaultPolicyEngine> currentEngine = new AtomicReference<>(engine(false));
    private final PolicyEngine engine = new PolicyEngine() {
        public AuthorizationDecision evaluate(AuthorizationRequest request) { return currentEngine.get().evaluate(request); }
        public String revision() { return currentEngine.get().revision(); }
    };
    private final ApprovalService service = new ApprovalService(engine, store, clock, audit, new DefaultParameterSanitizer());

    private DefaultPolicyEngine engine(boolean deny) {
        return new DefaultPolicyEngine(PolicySet.builder("test", "1").rules(List.of(
            PolicyRule.builder("review", deny ? RuleEffect.DENY : RuleEffect.APPROVAL_REQUIRED)
                .targetActions(Set.of("refund")).build())).build());
    }
    private AgentIdentity identity(String id, String permission) {
        return AgentIdentity.builder().agentId(id).permission(permission).issuedAt(now.minusSeconds(60)).expiresAt(now.plusSeconds(3600)).build();
    }
    private AuthorizationRequest request(String subject, int amount) {
        return AuthorizationRequest.of(identity(subject, "refund"), Action.of("refund", Map.of("amount", amount, "password", "secret")),
            Resource.of("order", "1"), AuthorizationContext.of("production"));
    }
    private String approved() {
        String id = service.request(request("agent", 10), Duration.ofMinutes(5)).id();
        service.approve(id, identity("human", "agentguard.approval.approve"));
        return id;
    }
    @Test void exactApprovedRequestExecutesOnceAndAuditContainsNoSecret() {
        String id = approved();
        Object amount = service.execute(id, request("agent", 10), input -> input.action().parameters().get("amount"));
        assertThat(amount).isEqualTo(10);
        assertThatThrownBy(() -> service.execute(id, request("agent", 10), input -> "again")).isInstanceOf(AgentAccessDeniedException.class);
        assertThat(audit.getEvents().toString()).doesNotContain("password=secret");
        assertThat(audit.getEvents().getLast().metadata()).containsEntry("phase", "EXECUTION_SUCCEEDED");
        assertThat(store.find(id).orElseThrow().toString()).doesNotContain("password");
    }
    @Test void changedArgumentsIdentityResourceOrPolicyAreRejected() {
        String id = approved();
        assertThatThrownBy(() -> service.execute(id, request("agent", 11), input -> "no")).isInstanceOf(AgentAccessDeniedException.class);
        assertThatThrownBy(() -> service.execute(id, request("other", 10), input -> "no")).isInstanceOf(AgentAccessDeniedException.class);
        var original = request("agent", 10);
        var otherResource = AuthorizationRequest.of(original.subject(), original.action(), Resource.of("order", "2"), original.context());
        assertThatThrownBy(() -> service.execute(id, otherResource, input -> "no")).isInstanceOf(AgentAccessDeniedException.class);
        currentEngine.set(engine(true));
        assertThatThrownBy(() -> service.execute(id, original, input -> "no")).isInstanceOf(AgentAccessDeniedException.class);
    }
    @Test void changedPolicyWithSameAllowDecisionStillInvalidatesApproval() {
        String id = approved();
        currentEngine.set(new DefaultPolicyEngine(PolicySet.builder("changed-policy", "1").build()));
        assertThatThrownBy(() -> service.execute(id, request("agent", 10), input -> "no"))
            .isInstanceOf(AgentAccessDeniedException.class).hasMessageContaining("Policy changed");
    }
    @Test void unauthorizedAndSelfApprovalsFail() {
        String id = service.request(request("agent", 10), Duration.ofMinutes(5)).id();
        assertThatThrownBy(() -> service.approve(id, identity("stranger", "read"))).isInstanceOf(AgentAccessDeniedException.class);
        assertThatThrownBy(() -> service.approve(id, identity("agent", "agentguard.approval.approve"))).isInstanceOf(AgentAccessDeniedException.class);
        assertThatThrownBy(() -> service.execute(id, request("agent", 10), input -> "no")).isInstanceOf(AgentAccessDeniedException.class);
    }
    @Test void expiryIsEnforcedAtTheBoundaryAndIgnoresCallerTimestamp() {
        String id = approved(); currentTime.set(now.plusSeconds(300));
        assertThatThrownBy(() -> service.execute(id, request("agent", 10), input -> "no")).isInstanceOf(AgentAccessDeniedException.class);
    }
    @Test void deniedRequestCannotCreateApproval() {
        currentEngine.set(engine(true));
        assertThatThrownBy(() -> service.request(request("agent", 10), Duration.ofMinutes(5))).isInstanceOf(AgentAccessDeniedException.class);
    }
    @Test void failureConsumesTicketAndConcurrentReplayExecutesAtMostOnce() throws Exception {
        String id = approved(); var count = new AtomicInteger();
        try (var pool = Executors.newFixedThreadPool(8)) {
            List<Future<?>> futures = new ArrayList<>();
            for (int i=0; i<8; i++) futures.add(pool.submit(() -> {
                try { service.execute(id, request("agent", 10), input -> { count.incrementAndGet(); throw new IllegalStateException("business-secret"); }); }
                catch (IllegalStateException | AgentAccessDeniedException expected) { }
            }));
            for (var future : futures) future.get();
        }
        assertThat(count).hasValue(1);
        assertThat(store.find(id).orElseThrow().state()).isEqualTo(ApprovalTicket.State.CONSUMED);
        assertThat(audit.getEvents().toString()).doesNotContain("business-secret");
    }
    @Test void executionReceivesImmutableArgumentSnapshot() {
        String id = approved();
        service.execute(id, request("agent", 10), input -> {
            assertThatThrownBy(() -> input.action().parameters().put("amount", 100)).isInstanceOf(UnsupportedOperationException.class);
            return "ok";
        });
    }
    @Test void rejectedTicketCannotExecute() {
        String id = service.request(request("agent", 10), Duration.ofMinutes(5)).id();
        service.reject(id, identity("human", "agentguard.approval.approve"));
        assertThatThrownBy(() -> service.execute(id, request("agent", 10), input -> "no")).isInstanceOf(AgentAccessDeniedException.class);
    }
}
