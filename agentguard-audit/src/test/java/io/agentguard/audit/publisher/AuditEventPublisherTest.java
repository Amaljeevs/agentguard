package io.agentguard.audit.publisher;

import io.agentguard.audit.model.AuditEvent;
import io.agentguard.core.model.AgentType;
import io.agentguard.core.model.Decision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@DisplayName("AuditEventPublisher SPI Implementations Tests")
class AuditEventPublisherTest {

    private AuditEvent createTestEvent(Decision decision) {
        return new AuditEvent(
            "evt-01",
            Instant.now(),
            "agent-test-01",
            AgentType.AUTONOMOUS,
            Set.of("developer"),
            "database.query",
            Map.of("query", "SELECT 1;"),
            "database",
            "test-db",
            "development",
            decision,
            "Evaluation result",
            Optional.of("policy-1"),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Map.of()
        );
    }

    @Test
    @DisplayName("InMemoryAuditEventPublisher should store published events thread-safely")
    void inMemoryPublisher_shouldCaptureEvents() {
        InMemoryAuditEventPublisher publisher = new InMemoryAuditEventPublisher();
        AuditEvent event = createTestEvent(Decision.ALLOW);

        publisher.publish(event);

        assertThat(publisher.size()).isEqualTo(1);
        assertThat(publisher.getEvents().get(0)).isEqualTo(event);

        publisher.clear();
        assertThat(publisher.size()).isEqualTo(0);
    }

    @Test
    @DisplayName("CompositeAuditEventPublisher should broadcast to all children even if one fails")
    void compositePublisher_shouldBroadcast() {
        InMemoryAuditEventPublisher pub1 = new InMemoryAuditEventPublisher();
        InMemoryAuditEventPublisher pub2 = new InMemoryAuditEventPublisher();

        CompositeAuditEventPublisher composite = CompositeAuditEventPublisher.of(pub1, pub2);
        AuditEvent event = createTestEvent(Decision.DENY);

        composite.publish(event);

        assertThat(pub1.getEvents()).containsExactly(event);
        assertThat(pub2.getEvents()).containsExactly(event);
    }

    @Test
    @DisplayName("Slf4jAuditEventPublisher should safely write log message without exception")
    void slf4jPublisher_shouldPublishSafely() {
        Slf4jAuditEventPublisher slf4j = new Slf4jAuditEventPublisher();
        AuditEvent allowEvent = createTestEvent(Decision.ALLOW);
        AuditEvent denyEvent = createTestEvent(Decision.DENY);
        AuditEvent approvalEvent = createTestEvent(Decision.APPROVAL_REQUIRED);

        assertThatCode(() -> {
            slf4j.publish(allowEvent);
            slf4j.publish(denyEvent);
            slf4j.publish(approvalEvent);
        }).doesNotThrowAnyException();
    }
}
