package io.agentguard.spring.metrics;

import io.agentguard.core.model.Decision;
import io.agentguard.core.model.RiskLevel;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("MicrometerAgentGuardMetrics Tests")
class MicrometerAgentGuardMetricsTest {

    @Test
    @DisplayName("Should record decisions and latencies with low-cardinality tags")
    void shouldRecordDecisionsAndLatencies() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        MicrometerAgentGuardMetrics metrics = new MicrometerAgentGuardMetrics(registry);

        metrics.recordDecision(Decision.ALLOW, RiskLevel.LOW, Duration.ofMillis(5));
        metrics.recordDecision(Decision.DENY, RiskLevel.HIGH, Duration.ofMillis(12));
        metrics.recordDecision(Decision.APPROVAL_REQUIRED, RiskLevel.CRITICAL, Duration.ofMillis(20));

        double allowCount = registry.get("agentguard.authorization.decisions")
            .tag("decision", "ALLOW")
            .tag("risk", "LOW")
            .counter().count();
        assertThat(allowCount).isEqualTo(1.0);

        double denyCount = registry.get("agentguard.authorization.decisions")
            .tag("decision", "DENY")
            .tag("risk", "HIGH")
            .counter().count();
        assertThat(denyCount).isEqualTo(1.0);

        double approvalCount = registry.get("agentguard.authorization.decisions")
            .tag("decision", "APPROVAL_REQUIRED")
            .tag("risk", "CRITICAL")
            .counter().count();
        assertThat(approvalCount).isEqualTo(1.0);

        assertThat(registry.get("agentguard.authorization.latency").timers()).isNotEmpty();
    }

    @Test
    @DisplayName("Should record approval lifecycle events and errors")
    void shouldRecordApprovalEventsAndErrors() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        MicrometerAgentGuardMetrics metrics = new MicrometerAgentGuardMetrics(registry);

        metrics.recordApprovalEvent("created");
        metrics.recordApprovalEvent("approved");
        metrics.recordApprovalEvent("consumed");
        metrics.recordError("access_denied");

        assertThat(registry.get("agentguard.approval.events").tag("event", "created").counter().count()).isEqualTo(1.0);
        assertThat(registry.get("agentguard.approval.events").tag("event", "approved").counter().count()).isEqualTo(1.0);
        assertThat(registry.get("agentguard.approval.events").tag("event", "consumed").counter().count()).isEqualTo(1.0);
        assertThat(registry.get("agentguard.authorization.errors").tag("error_type", "access_denied").counter().count()).isEqualTo(1.0);
    }
}

