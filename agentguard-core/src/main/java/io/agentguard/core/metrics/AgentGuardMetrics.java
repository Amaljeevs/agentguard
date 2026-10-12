package io.agentguard.core.metrics;

import io.agentguard.core.model.Decision;
import io.agentguard.core.model.RiskLevel;

import java.time.Duration;

/**
 * Pluggable metrics interface for AgentGuard authorization and governance.
 * Enforces strictly low-cardinality tags:
 * - NEVER exposes agent IDs, raw resources, arguments, or secrets.
 */
public interface AgentGuardMetrics {

    void recordDecision(Decision decision, RiskLevel risk, Duration duration);

    void recordApprovalEvent(String eventType);

    void recordError(String errorType);

    AgentGuardMetrics NOOP = new AgentGuardMetrics() {
        @Override
        public void recordDecision(Decision decision, RiskLevel risk, Duration duration) {}

        @Override
        public void recordApprovalEvent(String eventType) {}

        @Override
        public void recordError(String errorType) {}
    };
}

