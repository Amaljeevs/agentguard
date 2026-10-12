package io.agentguard.spring.metrics;

import io.agentguard.core.metrics.AgentGuardMetrics;
import io.agentguard.core.model.Decision;
import io.agentguard.core.model.RiskLevel;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Production-ready Micrometer implementation of {@link AgentGuardMetrics}.
 * Uses strictly low-cardinality tags:
 * - decision (ALLOW, DENY, APPROVAL_REQUIRED)
 * - risk (LOW, MEDIUM, HIGH, CRITICAL)
 * - event (created, approved, denied, expired, consumed)
 * - error_type (access_denied, authentication_failed, etc.)
 */
public final class MicrometerAgentGuardMetrics implements AgentGuardMetrics {

    private final MeterRegistry registry;

    public MicrometerAgentGuardMetrics(MeterRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
    }

    @Override
    public void recordDecision(Decision decision, RiskLevel risk, Duration duration) {
        String dec = decision != null ? decision.name() : "UNKNOWN";
        String rk = risk != null ? risk.name() : "UNKNOWN";

        Counter.builder("agentguard.authorization.decisions")
            .description("Count of AgentGuard authorization decisions")
            .tag("decision", dec)
            .tag("risk", rk)
            .register(registry)
            .increment();

        if (duration != null) {
            Timer.builder("agentguard.authorization.latency")
                .description("Latency of AgentGuard policy evaluations")
                .tag("decision", dec)
                .tag("risk", rk)
                .register(registry)
                .record(duration.toNanos(), TimeUnit.NANOSECONDS);
        }
    }

    @Override
    public void recordApprovalEvent(String eventType) {
        String evt = eventType != null ? eventType.toLowerCase() : "unknown";
        Counter.builder("agentguard.approval.events")
            .description("Count of AgentGuard approval lifecycle events")
            .tag("event", evt)
            .register(registry)
            .increment();
    }

    @Override
    public void recordError(String errorType) {
        String err = errorType != null ? errorType.toLowerCase() : "unknown";
        Counter.builder("agentguard.authorization.errors")
            .description("Count of AgentGuard authorization errors")
            .tag("error_type", err)
            .register(registry)
            .increment();
    }
}

